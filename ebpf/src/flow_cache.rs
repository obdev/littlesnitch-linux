// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    FilterEngineConnection, context::Context, dns_cache::name_for_address,
    event_queue::enqueue_event, ip_parser::HeaderInfos, kernel_filter_model::KernelFilterModel,
    socket_properties::get_socket_properties,
};
use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC, helpers::generated::bpf_get_socket_cookie, macros::map,
    maps::HashMap,
};
use common::{
    StringId,
    bitset::BitSet,
    event::*,
    flow_types::*,
    network_filter::{
        filter_engine::FilterEngine, filter_model::FilterModel,
        port_table_search::SpecificPortTableSearch,
    },
};
use core::mem::transmute;
use network_types::ip::IpProto;

const REPORT_TCPIP_FRAMES: bool = false;

#[map]
pub static ACTIVE_FLOWS: HashMap<FlowIdentifier, FlowProperties> =
    HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);

impl Context {
    fn update_properties(
        &self,
        properties: &mut FlowProperties,
        identifier: &FlowIdentifier,
        header_infos: &HeaderInfos,
        mut changes: BitSet, // changes which occurred so far
    ) {
        let mut bytes = self.skb.len() as u64;
        let payload = bytes.saturating_sub(header_infos.payload_offset as _);
        if !REPORT_TCPIP_FRAMES {
            bytes = payload;
        }
        // The eBPF verifier is much faster when we maintain `changes` and `should_send_event`
        // separately.
        let mut should_send_event = changes.raw() != 0 || bytes != 0;
        properties.last_activity = self.timestamp;
        if properties.socket_cookie == 0 {
            properties.socket_cookie = unsafe { bpf_get_socket_cookie(self.skb.skb as _) };
            // The socket_cookie may legitimately be 0 for incoming packets in some cases.
        }
        if !properties.process_pair.is_known() && properties.socket_cookie != 0 {
            // ICMP packets are usually handled by the kernel, thus no associated process.
            // Inbound packets are often not yet associated with a socket and process.
            // In both cases the current process may be any running process not related to the
            // network packet.

            // We would like to use the code below to obtain a socket owner for those sockets
            // which were already open and connected when we started, but the lookup code
            // is obviously too much complexity for the ebpf verifier. Maybe try again if we
            // manage to reduce complexity of conversion to our node IDs.
            // let register_on_demand = !self.is_inbound
            //     && payload != 0
            //     && !(identifier.protocol == IpProto::Icmp as _
            //         || identifier.protocol == IpProto::Ipv6Icmp as _);
            let register_on_demand = false;
            if let Some(socket_properties) =
                get_socket_properties(properties.socket_cookie, register_on_demand)
            {
                properties.process_pair = socket_properties.owner.clone();
                if properties.process_pair.is_known() {
                    should_send_event = true;
                    changes += EXECUTABLE_UPDATED;
                }
            }
        }
        if properties.remote_name == StringId::none() {
            properties.remote_name =
                name_for_address(&identifier.remote_address, &properties.process_pair);
            if properties.remote_name != StringId::none() {
                should_send_event = true;
                changes += REMOTE_NAME_UPDATED;
            }
        }
        enqueue_event(|event| {
            event.connection_identifier.process_pair = properties.process_pair.clone();
            event.connection_identifier.remote_address = identifier.remote_address.clone();
            event.connection_identifier.remote_name = properties.remote_name;
            event.connection_identifier.is_inbound = properties.is_inbound;
            event.connection_identifier.protocol = identifier.protocol as _;
            event.connection_identifier.port = identifier.public_port(properties.is_inbound);
            if let Some(model) = KernelFilterModel::shared()
                && let Some(metainfo) = model.metainfo()
                && (matches!(properties.reason, VerdictReason::NotYetDetermined)
                    || properties.ruleset_generation != metainfo.ruleset_generation)
            {
                let mut search_spec = SpecificPortTableSearch::new(metainfo.default_verdict);
                model.evaluate_network_filter(
                    FilterEngineConnection::wrap(&event.connection_identifier),
                    &mut search_spec,
                );
                properties.ruleset_generation = metainfo.ruleset_generation;
                (properties.verdict, properties.reason) = search_spec.result();
            }
            if properties.verdict == Verdict::Deny {
                changes += BLOCKED;
                changes -= CONNECT;
                bytes = 0;
            }
            if should_send_event {
                event.payload.ephemeral_port = identifier.private_port(properties.is_inbound);
                event.payload.changes = changes;
                event.payload.verdict_reason = properties.reason.clone();
                if self.is_inbound {
                    event.payload.bytes_sent = 0;
                    event.payload.bytes_received = bytes;
                } else {
                    event.payload.bytes_sent = bytes;
                    event.payload.bytes_received = 0;
                }
                true // really enqueue
            } else {
                false
            }
        });
    }

    fn decide_flow_direction(
        &self,
        properties: &mut FlowProperties,
        flow_identifier: &FlowIdentifier,
        header_infos: &HeaderInfos,
    ) {
        // decide on connect direction
        if header_infos.tcp_syn {
            if !header_infos.tcp_ack {
                // this is a Connect request
                properties.is_inbound = self.is_inbound;
            } else {
                // this is a Connect accept from the server
                properties.is_inbound = !self.is_inbound;
            }
        } else {
            // We do not know for sure because we may have dropped into the middle of a
            // conversation. If we dropped into the middle of a TCP stream, judge by port number.
            if flow_identifier.protocol == IpProto::Tcp as u32 {
                // The bigger port number is probably the client
                properties.is_inbound = flow_identifier.local_port < flow_identifier.remote_port;
            } else {
                properties.is_inbound = self.is_inbound;
            }
        }
    }

    // Kept for reference: reading IPv6 addresses via `bpf_probe_read_kernel` is required because
    // a direct dereference (e.g. `*skb.local_ipv6()`) produces code that the eBPF verifier rejects.
    //
    // for reasons not comprehensible to me, the local port is given in host byte order while
    // the remote port is in network byte order. Swap accordingly.
    // let (local_address, remote_address) = if is_ipv6 {
    //     // We could use a simple `*skb.local_ipv6()` to read the value.
    //     // However, LLVM generates code which does not pass the verifier.
    //     // Using `bpf_probe_read_kernel()` gets around this problem.
    //     let local: [u32; 4] =
    //         unsafe { bpf_probe_read_kernel(skb.local_ipv6()) }.unwrap_or_default();
    //     let remote: [u32; 4] =
    //         unsafe { bpf_probe_read_kernel(skb.remote_ipv6()) }.unwrap_or_default();
    //     (IpAddress::v6(local), IpAddress::v6(remote))
    // } else {
    //     (
    //         IpAddress::v4(skb.local_ipv4()),
    //         IpAddress::v4(skb.remote_ipv4()),
    //     )
    // };

    pub fn update_from_packet(&self) -> Option<Verdict> {
        // local_ip*(), remote_ip*(), local_port() and remote_port() are properties of the bind()
        // socket call. They may be invalid for unbound sockets.
        let identifier = &mut self.buffers().flow_identifier;
        let header_infos = self.parse_headers(identifier)?;

        // Ignore (and allow) ICMP, except echo, which goes through the filter as everything else.
        match (unsafe { transmute(identifier.protocol as u8) }, header_infos.icmp_type) {
            (IpProto::Icmp, 0)
            | (IpProto::Icmp, 8)
            | (IpProto::Ipv6Icmp, 128)
            | (IpProto::Ipv6Icmp, 129) => {}
            (IpProto::Icmp, _) | (IpProto::Ipv6Icmp, _) => return Some(Verdict::Allow),
            _ => {}
        }

        let process_pair: &ProcessPair;
        let verdict;
        let properties_ptr = if let Some(properties_ptr) = ACTIVE_FLOWS.get_ptr_mut(&*identifier) {
            properties_ptr
        } else {
            let properties = &mut self.buffers().flow_properties;
            properties.remote_name = StringId::none();
            properties.socket_cookie = unsafe { bpf_get_socket_cookie(self.skb.skb as _) };
            if properties.socket_cookie == 0
                && !(header_infos.tcp_syn
                    && !header_infos.tcp_ack
                    && !header_infos.tcp_rst
                    && !header_infos.tcp_fin)
            {
                // Do not accept every network packet as new flow. Sometimes we receive packets for
                // old (already deleted) flows which cannot be delivered to a process. If this is
                // a TCP packet which does not have SYN without ACK set and it cannot be attributed
                // to a socket, just allow and ignore.
                return Some(Verdict::Allow);
            }
            properties.is_closed = false;
            properties.verdict = Verdict::Allow;
            properties.reason = VerdictReason::NotYetDetermined;
            properties.process_pair.executable_pair.connecting = None;
            properties.process_pair.executable_pair.parent = None;
            properties.process_pair.executable_pair.uid = 0;
            self.decide_flow_direction(properties, identifier, &header_infos);
            // ensure we pass by reference, not by value by using `&*`
            _ = ACTIVE_FLOWS.insert(&*identifier, &*properties, 0);
            let Some(properties_ptr) =  ACTIVE_FLOWS.get_ptr_mut(&*identifier) else {
                return Some(Verdict::Allow); // unexpected failure, let it pass
            };
            properties_ptr
        };
        let properties = unsafe { &mut *properties_ptr };
        self.update_properties(properties, identifier, &header_infos, BitSet::empty());
        process_pair = &properties.process_pair;
        verdict = properties.verdict;
        if identifier.protocol == IpProto::Udp as u32 && identifier.remote_port == 53 {
            self.process_dns_packet(header_infos.payload_offset, process_pair);
        }
        Some(verdict)
    }
}
