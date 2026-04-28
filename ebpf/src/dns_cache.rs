// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use core::cmp;

use aya_ebpf::{helpers::generated::bpf_skb_load_bytes, macros::map, maps::LruHashMap};
use common::{
    NanoTime, StringId,
    bpf_string::BpfString,
    dns_types::{DnsIpv4Key, DnsIpv6Key, DnsNameKey},
    flow_types::{IpAddress, LOCALHOST_ADDRESS, LOCALHOST_MASK, ProcessPair},
    repeat::{LoopReturn, repeat_closure},
};

use crate::{
    context::{Context, DnsMessageHeader},
    dn_expand::dn_expand,
    strings_cache::{self, identifier_for_string},
};

const MAX_QUERY_AGE: i64 = 10 * 1000 * 1000 * 1000; // 10 seconds in nanoseconds

const RR_CLASS_INET: u16 = 1;

const RR_TYPE_A: u16 = 1;
const RR_TYPE_AAAA: u16 = 28;
const RR_TYPE_CNAME: u16 = 5;

#[map]
static DNS_QUERIES: LruHashMap<DnsNameKey, NanoTime> = LruHashMap::with_max_entries(8192, 0);

#[map]
static DNS_CNAMES: LruHashMap<DnsNameKey, StringId> = LruHashMap::with_max_entries(8192, 0);

#[map]
static DNS_IPV4ADDR: LruHashMap<DnsIpv4Key, StringId> = LruHashMap::with_max_entries(8192, 0);

#[map]
static DNS_IPV6ADDR: LruHashMap<DnsIpv6Key, StringId> = LruHashMap::with_max_entries(8192, 0);

pub trait PacketProvider {
    fn len(&self) -> usize;
    fn load_bytes(&self, offset: usize, destination: *mut u8, len: usize) -> Option<usize>;
}

trait IsOutdated {
    fn is_outdated(&self, now: NanoTime) -> bool;
}
impl IsOutdated for NanoTime {
    fn is_outdated(&self, now: NanoTime) -> bool {
        now.0 - self.0 > MAX_QUERY_AGE
    }
}

/*
We don't need multiple names leading to an IP address. Only the most recent. We can use only one
name anyway. The DNS cache is therfore organized in the following mappings:

    (pid, query_name) -> timestamp

    (pid, CNAME) -> query_name
    (pid, IPV4ADDRESS) -> query_name
    (pid, IPV6ADDRESS) -> query_name


    a query for a CNAME from a recent query response is not stored as query

    When a query comes in:
        - if the name is a cname returned by a recent query, ignore it
        - otherwise update timestamp for query

    When a response comes in:
        for each Resource Record
        - if not CNAME/IPv4/6: ignore
        - find query for the response
            - if no direct query found, go through cnames for recent query
            - if query not recent or cname query not recent, ignore
        - store (CNAME/IP) -> query
*/

/*
We trust the name server to echo back the question correctly in the response. We try to protect
against malicious processes to a certian degree, but not malicious name servers.

Information per flow:
    - tx buffer and rx buffer (must hold up to one NAME entry)
    - rx and tx messages are complete (defragmented IP)

 */

impl Context {
    // only called for packets at the DNS client's socket, not local DNS server socket
    // By preventing inlining, local variable stack space is allocated only if this function is
    // called, which saves stack space for rule evaluation.
    #[inline(never)]
    pub fn process_dns_packet(&self, payload_offset: usize, process_pair: &ProcessPair) {
        let dns_msg_start_index = payload_offset as u16;
        let mut index = payload_offset;
        let dns_msg_header = &mut self.buffers().dns_message_header;
        let opcode = (dns_msg_header.opcode_and_flags >> 3) & 0xf;
        if opcode != 0 {
            return; // not a standard query
        }
        if self.parse_header(&mut index, dns_msg_header) == None
            || dns_msg_header.question_count != 1
        {
            return; // unexpected counts
        }
        let is_query = (dns_msg_header.opcode_and_flags & 0x80) == 0;
        // There is always a question because the response echos back the question
        let question = self.parse_question(&mut index, dns_msg_start_index);
        if is_query {
            let name_key = DnsNameKey { name: question };
            if let Some(query_name) = unsafe { DNS_CNAMES.get(&name_key) } {
                let query_key = DnsNameKey { name: *query_name };
                if let Some(query_time) = unsafe { DNS_QUERIES.get(&query_key) } {
                    if !query_time.is_outdated(self.timestamp) {
                        // We have a recent query which returned this CNAME, so ignore
                        return;
                    }
                }
            }
            _ = DNS_QUERIES.insert(&name_key, &self.timestamp, 0);
        } else {
            let sane_answer_count = cmp::min(64, dns_msg_header.answer_count) as u64;
            repeat_closure(sane_answer_count as _, |_| {
                self.parse_answer(&mut index, process_pair, self.timestamp, dns_msg_start_index)
            });
        }
    }

    fn parse_header(&self, index: &mut usize, header: &mut DnsMessageHeader) -> Option<()> {
        let header_len = size_of::<DnsMessageHeader>();
        if self.len() < *index + header_len {
            return None; // not enough data for header
        }
        self.load_to_buffer(*index, header)?;
        *index += header_len;
        header.question_count = u16::from_be(header.question_count);
        header.answer_count = u16::from_be(header.answer_count);
        header.authority_count = u16::from_be(header.authority_count);
        header.additional_count = u16::from_be(header.additional_count);
        Some(())
    }

    fn parse_question(&self, index: &mut usize, dns_msg_start_index: u16) -> StringId {
        let string_buffer = &mut self.buffers().string;
        string_buffer.clear();
        dn_expand(self, index, dns_msg_start_index, string_buffer);
        let question = strings_cache::identifier_for_string(string_buffer);
        *index += 4; // skip question class (u16) and type (u16), we don't care
        question
    }

    fn parse_answer(
        &self,
        index: &mut usize,
        process_pair: &ProcessPair,
        now: NanoTime,
        dns_msg_start_index: u16,
    ) -> LoopReturn {
        let string_buffer = &mut self.buffers().string;
        string_buffer.clear();
        dn_expand(self, index, dns_msg_start_index, string_buffer);
        let header = &mut self.buffers().dns_rr_header;
        let header_len = size_of_val(header);
        if *index + header_len > self.len() {
            return LoopReturn::LoopBreak;
        }
        if self.load_to_buffer(*index, header).is_none() {
            return LoopReturn::LoopBreak;
        }
        *index += header_len;
        let data_class = u16::from_be(header.data_class);
        let data_type = u16::from_be(header.data_type);
        let data_len = u16::from_be(header.data_length) as usize;
        if *index + data_len > self.len() {
            return LoopReturn::LoopBreak; // data does not fit into message
        }
        if data_class == RR_CLASS_INET {
            let rr_name = identifier_for_string(string_buffer);
            let name_key = DnsNameKey { name: rr_name };
            // When a response comes in:
            //     - find query for the response
            //          - if no query found {
            //              query = find from cname
            //          } else {
            //              query = query
            //          }
            //         - if no direct query found, go through cnames for recent query
            //         - if query not recent or cname query not recent, ignore
            //     - store (CNAME/IP) -> query
            let (query_name, time) = match unsafe { DNS_QUERIES.get(&name_key) } {
                Some(time) => (rr_name, *time),
                None => {
                    if let Some(query_name) = unsafe { DNS_CNAMES.get(&name_key) } {
                        let name_key = DnsNameKey { name: *query_name };
                        if let Some(time) = unsafe { DNS_QUERIES.get(&name_key) } {
                            (*query_name, *time)
                        } else {
                            (StringId::none(), NanoTime(0))
                        }
                    } else {
                        (StringId::none(), NanoTime(0))
                    }
                }
            };
            if query_name != StringId::none() && !time.is_outdated(now) {
                match data_type {
                    RR_TYPE_A => {
                        _ = self.parse_a_record(query_name, process_pair, *index, data_len)
                    }
                    RR_TYPE_AAAA => {
                        _ = self.parse_aaaa_record(query_name, process_pair, *index, data_len)
                    }
                    RR_TYPE_CNAME => {
                        _ = self.parse_cname_record(
                            query_name,
                            process_pair,
                            *index,
                            dns_msg_start_index,
                            string_buffer,
                        )
                    }
                    _ => {} // ignore
                }
            }
        }
        *index += data_len;
        LoopReturn::LoopContinue // we can continue to next answer
    }

    fn parse_a_record(
        &self,
        query_name: StringId,
        _process_pair: &ProcessPair,
        index: usize,
        len: usize,
    ) -> Option<()> {
        if len != 4 {
            return None; // not a valid IPv4 record
        }
        let mut address = 0u32;
        self.load_to_buffer(index, &mut address)?;
        // Ignore loopback addresses in response. That's common with PiHole and the frontend
        // would show the blocked name as remote for localhost connections.
        if address & LOCALHOST_MASK != LOCALHOST_ADDRESS && address != 0 {
            _ = DNS_IPV4ADDR.insert(&DnsIpv4Key { address }, &query_name, 0);
        }
        Some(())
    }

    fn parse_aaaa_record(
        &self,
        query_name: StringId,
        _process_pair: &ProcessPair,
        index: usize,
        len: usize,
    ) -> Option<()> {
        if len != 16 {
            return None; // not a valid IPv6 record
        }
        let mut address = [0u32; 4];
        self.load_to_buffer(index, &mut address)?;
        // Ignore loopback addresses in response. That's common with PiHole and the frontend
        // would show the blocked name as remote for localhost connections.
        // IPv6 loopback is ::1 or ::0 (the unspecified address).
        if address[0] | address[1] | address[2] | (address[3] & !1u32.to_be()) != 0 {
            _ = DNS_IPV6ADDR.insert(&DnsIpv6Key { address }, &query_name, 0);
        }
        Some(())
    }

    fn parse_cname_record(
        &self,
        query_name: StringId,
        _process_pair: &ProcessPair,
        mut index: usize,
        dns_msg_start_index: u16,
        string_buffer: &mut BpfString,
    ) -> Option<()> {
        string_buffer.clear();
        dn_expand(self, &mut index, dns_msg_start_index, string_buffer);
        // ignore len, we anyway don't know what to do if we exceed it
        let cname = identifier_for_string(string_buffer);
        let cname_key = DnsNameKey { name: cname };
        _ = DNS_CNAMES.insert(&cname_key, &query_name, 0);
        Some(())
    }
}

pub fn name_for_address(address: &IpAddress, _process_pair: &ProcessPair) -> StringId {
    if address.is_v6() {
        let key = DnsIpv6Key { address: *address.address() };
        *unsafe { DNS_IPV6ADDR.get(&key) }.unwrap_or(&StringId::none())
    } else {
        let key = DnsIpv4Key { address: address.address()[0] };
        *unsafe { DNS_IPV4ADDR.get(&key) }.unwrap_or(&StringId::none())
    }
}

impl PacketProvider for Context {
    fn len(&self) -> usize {
        self.skb.len() as _
    }

    fn load_bytes(&self, offset: usize, destination: *mut u8, len: usize) -> Option<usize> {
        let ret = unsafe {
            bpf_skb_load_bytes(self.skb.skb.cast(), offset as u32, destination as _, len as u32)
        };
        if ret == 0 { Some(len) } else { None }
    }
}
