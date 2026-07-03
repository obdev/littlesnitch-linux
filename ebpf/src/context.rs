// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use aya_ebpf::helpers::generated::bpf_ktime_get_coarse_ns;
use aya_ebpf::programs::sk_buff::SkBuff;
use aya_ebpf::{macros::map, maps::PerCpuArray};
use common::flow_types::SocketProperties;
use common::{NanoTime, StringId};
use common::{
    bpf_string::BpfString,
    flow_types::{FlowIdentifier, FlowProperties},
    node_cache::MAX_PATH_COMPONENTS,
};
use network_types::{
    ip::{Ipv4Hdr, Ipv6Hdr},
    sctp::SctpHdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

// We use PerCpuArray for buffers to cope with concurrency issues. The same ebpf program is
// guaranteed not to run concurrently on the same CPU. However, different types of program
// may be scheduled concurrently on the same CPU, maybe even programs under the CGROUP section.
// We therefore use separate buffers for each program type.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ConcurrencyGroup {
    CgroupSkbIn = 0,
    CgroupSkbOut = 1,
    CgroupSockCreate = 2,
    CgroupSockConnect = 3,
    CgroupSendMsg = 4,
    FentryExec = 5,
    // If you extend, also extend max entries of `BUFFERS` below.
}

#[map]
static BUFFERS: PerCpuArray<StaticBuffers> =
    PerCpuArray::with_max_entries(ConcurrencyGroup::FentryExec as u32 + 1, 0);

pub struct Context {
    pub skb: SkBuff,
    buffers: *mut StaticBuffers, // access via `buffers()` function
    pub timestamp: NanoTime,
    pub is_inbound: bool,
}

pub struct StaticBuffers {
    pub flow_identifier: FlowIdentifier,
    pub flow_properties: FlowProperties,
    pub socket_properties: SocketProperties,
    pub ipv4_header: Ipv4Hdr,
    pub ipv6_header: Ipv6Hdr,
    pub sctp_header: SctpHdr,
    pub tcp_header: TcpHdr,
    pub udp_header: UdpHdr,
    pub ipv6_option: Ipv6Option,
    pub string: BpfString,
    pub dns_message_header: DnsMessageHeader,
    pub dns_rr_header: DnsResourceRecordHeader,
    pub string_ids: [StringId; MAX_PATH_COMPONENTS],
}

#[repr(C, packed)]
pub struct Ipv6Option {
    pub next_hdr: u8,
    pub length: u8,
    pub options: [u8; 6],
}

#[repr(C)]
pub struct DnsMessageHeader {
    pub transaction_id: u16,
    pub opcode_and_flags: u8,
    pub rcode_and_flags: u8,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

// Although the message itself may have the header misaligned, we read it into memory at an
// aligned location.
#[repr(C)]
pub struct DnsResourceRecordHeader {
    pub data_type: u16,
    pub data_class: u16,
    pub _ttl: [u16; 2], // represent as array to preserve 2 byte alignment
    pub data_length: u16,
}

impl StaticBuffers {
    pub fn get(group: ConcurrencyGroup) -> *mut Self {
        BUFFERS.get_ptr_mut(group as _).unwrap_or_default()
    }
}

impl Context {
    #[inline(always)]
    pub fn get(skb: SkBuff, is_inbound: bool) -> Option<Self> {
        let group = if is_inbound {
            ConcurrencyGroup::CgroupSkbIn
        } else {
            ConcurrencyGroup::CgroupSkbOut
        };
        let buffers = StaticBuffers::get(group);
        if buffers.is_null() {
            return None;
        }
        Some(Self {
            skb,
            buffers,
            timestamp: NanoTime(unsafe { bpf_ktime_get_coarse_ns() } as _),
            is_inbound,
        })
    }

    // Access to static buffers. By making mutable static buffers available from an immutable
    // Context reference, we circumvent Rust's protection against duplicate mutable borrow.
    // This is intentional: Otherwise we would have to pass the appropriate buffers down the
    // call hierarchy as function parameters, but the number of parameters is limited.
    // The idea of Context is to pass common parameters in a single reference.
    pub fn buffers(&self) -> &mut StaticBuffers {
        unsafe { &mut *self.buffers }
    }
}
