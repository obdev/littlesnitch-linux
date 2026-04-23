// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use aya_ebpf::helpers::generated::bpf_skb_load_bytes;
use common::flow_types::{FlowIdentifier, IpAddress};
use core::arch::asm;
use core::mem::transmute;
use network_types::ip::{IpProto, Ipv6Hdr};

use crate::context::Context;

// At the CGROUP SKB level where we intercept (socket level), packets have not Ethernet framing
// yet. They arrrive with IP v4 or v6 header.

// Information derived from TCP/IP headers
#[derive(Default)]
pub struct HeaderInfos {
    pub payload_offset: usize,
    pub tcp_ack: bool,
    pub tcp_fin: bool,
    pub tcp_rst: bool,
    pub tcp_syn: bool,
    pub icmp_type: u8,
}

const _AF_INET: u32 = 2;
const _AF_INET6: u32 = 10;

impl Context {
    // returns payload offset
    pub fn parse_headers(
        &self,
        flow_identifier: &mut FlowIdentifier,
        is_ipv6: bool,
    ) -> Option<HeaderInfos> {
        // We cannot use self.skb.family() to determine the protocol because it is possible to
        // send IPv4 packets on a socket opened with AF_INET6. Detect the protocol from the
        // ethernet header instead. We would need self.skb.family() if we would read the socket
        // addresses from skb, but we don't do that.
        // let is_ipv6 = self.skb.family() == AF_INET6;
        let next_proto_offset: usize;
        let protocol: u8;
        if is_ipv6 {
            let header = &mut self.buffers().ipv6_header;
            self.load_to_buffer(0, header)?;
            (protocol, next_proto_offset) = self.proto_and_offset(header.next_hdr as u8)?;
            if self.is_inbound {
                flow_identifier.remote_address =
                    IpAddress::v6(unsafe { transmute(header.src_addr) });
                flow_identifier.local_address =
                    IpAddress::v6(unsafe { transmute(header.dst_addr) });
            } else {
                flow_identifier.local_address =
                    IpAddress::v6(unsafe { transmute(header.src_addr) });
                flow_identifier.remote_address =
                    IpAddress::v6(unsafe { transmute(header.dst_addr) });
            }
        } else {
            let header = &mut self.buffers().ipv4_header;
            self.load_to_buffer(0, header)?;
            next_proto_offset = header.ihl() as _;
            protocol = header.proto as u8;
            if self.is_inbound {
                flow_identifier.remote_address = IpAddress::v4(u32::from_ne_bytes(header.src_addr));
                flow_identifier.local_address = IpAddress::v4(u32::from_ne_bytes(header.dst_addr));
            } else {
                flow_identifier.local_address = IpAddress::v4(u32::from_ne_bytes(header.src_addr));
                flow_identifier.remote_address = IpAddress::v4(u32::from_ne_bytes(header.dst_addr));
            }
        }
        flow_identifier.protocol = protocol as _;
        let mut header_infos = HeaderInfos::default();
        let source_port;
        let destination_port;
        (source_port, destination_port, header_infos.payload_offset) =
            match unsafe { transmute(protocol) } {
                IpProto::Icmp | IpProto::Ipv6Icmp => {
                    self.parse_icmp(next_proto_offset, &mut header_infos)?
                }
                IpProto::Tcp => self.parse_tcp(next_proto_offset, &mut header_infos)?,
                IpProto::Udp => self.parse_udp(next_proto_offset)?,
                IpProto::Sctp => self.parse_sctp(next_proto_offset)?,
                _ => {
                    // This inline assembler code is a workaround for a compiler bug or the verifier
                    // being too picky: The return register R0 contains an undefined value (a pointer
                    // to the stack) because the actual return value is too big to be passed in R0 and
                    // calling conventions dictate that the caller must provide a pointer for the
                    // result.
                    unsafe { asm!("r0 = 0", options(nostack, nomem)) };
                    return None;
                }
            };
        if self.is_inbound {
            flow_identifier.remote_port = source_port;
            flow_identifier.local_port = destination_port;
        } else {
            flow_identifier.local_port = source_port;
            flow_identifier.remote_port = destination_port;
        }
        Some(header_infos)
    }

    fn proto_and_offset(&self, mut next_header: u8) -> Option<(u8, usize)> {
        let mut offset = Ipv6Hdr::LEN;
        let option = &mut self.buffers().ipv6_option;
        // iterate over up to 10 option headers
        for _ in 0..10 {
            match next_header {
                0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140 | 253 | 254 => (),
                _ => return Some((next_header, offset)),
            }
            self.load_to_buffer(offset, option)?;
            offset += size_of_val(option) + 8 * option.length as usize;
            next_header = option.next_hdr;
        }
        None
    }

    /// Returns source and destination port numbers and payload offset on success.
    fn parse_icmp(
        &self,
        offset: usize,
        header_infos: &mut HeaderInfos,
    ) -> Option<(u16, u16, usize)> {
        let mut header = [0u8; 4];
        self.load_to_buffer(offset, &mut header)?;
        header_infos.icmp_type = header[0];
        Some((0, 0, offset + 4))
    }

    /// Returns source and destination port numbers and payload offset on success.
    fn parse_tcp(
        &self,
        offset: usize,
        header_infos: &mut HeaderInfos,
    ) -> Option<(u16, u16, usize)> {
        let header = &mut self.buffers().tcp_header;
        self.load_to_buffer(offset, header)?;
        header_infos.tcp_ack = header.ack() != 0;
        header_infos.tcp_syn = header.syn() != 0;
        header_infos.tcp_rst = header.rst() != 0;
        header_infos.tcp_fin = header.fin() != 0;
        Some((
            u16::from_be_bytes(header.source),
            u16::from_be_bytes(header.dest),
            offset + (unsafe { transmute::<_, [u8; 2]>(header._bitfield_1) }[0] >> 4) as usize * 4,
        ))
    }

    /// Returns source and destination port numbers and payload offset on success.
    fn parse_udp(&self, offset: usize) -> Option<(u16, u16, usize)> {
        let header = &mut self.buffers().udp_header;
        self.load_to_buffer(offset, header)?;
        Some((
            u16::from_be_bytes(header.src),
            u16::from_be_bytes(header.dst),
            offset + size_of_val(header),
        ))
    }

    /// Returns source and destination port numbers and payload offset on success.
    fn parse_sctp(&self, offset: usize) -> Option<(u16, u16, usize)> {
        let header = &mut self.buffers().sctp_header;
        self.load_to_buffer(offset, header)?;
        Some((
            u16::from_be_bytes(header.src),
            u16::from_be_bytes(header.dst),
            offset + size_of_val(header),
        ))
    }

    #[inline]
    pub fn load_to_buffer<T>(&self, offset: usize, buffer: &mut T) -> Option<()> {
        let ret = unsafe {
            bpf_skb_load_bytes(
                self.skb.skb as *const _,
                offset as u32,
                buffer as *mut T as _,
                size_of::<T>() as u32,
            )
        };
        if ret == 0 { Some(()) } else { None }
    }
}
