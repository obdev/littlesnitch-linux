// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    ByteAtOffset,
    bpf_string::BpfString,
    ext_order::ExtOrder,
    network_filter::{
        domain_name_page::DomainNamePage,
        rule_page::{BYTES_PER_RULE_PAGE, RulePage},
        rule_types::{DirectionPattern, ExePatternId, Port, ProtocolPattern, RuleId},
    },
};
use core::{cmp::Ordering, fmt::Debug, ops::Range};

/// This module defines the BinaryRule type, all types which can be substituted for the
/// `EndointAddress` parameter and the type `PortTableEntry`, which defines matching of port,
/// protocol and direction.

#[cfg_attr(feature = "user", derive(Clone, Copy))]
#[derive(Debug)]
#[repr(C)]
pub struct BinaryRule<BinaryEndpoint: BinaryEndpointTrait> {
    pub exe_pattern: ExePatternId,
    pub port_table: PortTableReference,
    pub endpoint: BinaryEndpoint,
}

pub type NameBinaryRule = BinaryRule<NameBinaryEndpoint>;
pub type Ipv4BinaryRule = BinaryRule<Ipv4BinaryEndpoint>;
pub type Ipv6BinaryRule = BinaryRule<Ipv6BinaryEndpoint>;
pub type AnyEndpointBinaryRule = BinaryRule<()>;

#[derive(Clone, Debug)]
pub struct PortTableEntry {
    pub rule_id: RuleId,
    pub port: Port,   // start port or, when combined with len, two ports
    type_and_len: u8, // 2 bit type, 6 bit len with exponent
    protocol_and_direction: u8,
}

// encoding of type_and_len:
// 0 0 x x xxxx  len 1 .. 63   len == 0: full port range
// 0 1 x x xxxx  len (0 .. 63) << 6
// 1 0 0 0 xxxx  len (0 .. 15) << 12
// 1 0 0 1 xxxx
// 1 0 1 0 xxxx
// 1 0 1 1 1111  end of list
// 1 1 b b bbbb  2 ports each 11 bits

#[derive(PartialEq, Eq)]
pub enum PortEntryType {
    AnyPort,
    PortAndLength,
    TwoPorts,
    Stop,
}

impl PortTableEntry {
    #[inline(always)]
    pub fn protocol_and_direction(
        direction_pattern: DirectionPattern,
        protocol_pattern: ProtocolPattern,
    ) -> u8 {
        direction_pattern.bits() << 6 | protocol_pattern.bits()
    }

    // We cannot use a Vec here because we are no_std and we want to have this function here
    // in the crate because it deals with the binary representation of the PortTableEntry.
    pub fn with_closed_port_range(
        protocol_and_direction: u8,
        rule_id: RuleId,
        range: Range<Port>,
    ) -> [Option<Self>; 3] {
        let mut result: [Option<Self>; 3] = Default::default();
        let mut start = range.start;
        let mut len = (range.end - start).wrapping_add(1);
        if len == 0 {
            result[0] = Some(Self {
                rule_id,
                port: 0,
                type_and_len: 0,
                protocol_and_direction,
            });
        } else {
            for i in [2usize, 1, 0] {
                let f: u16 = 1 << (6 * i);
                let x = len / f;
                if x != 0 {
                    let type_and_len = x as u8 | ((i as u8) << 6);
                    result[i] = Some(Self {
                        rule_id,
                        port: start,
                        type_and_len,
                        protocol_and_direction,
                    });
                    len -= x;
                    start += x;
                }
            }
        }
        result
    }

    pub fn with_two_ports(
        protocol_and_direction: u8,
        rule_id: RuleId,
        port1: u16,
        port2: u16,
    ) -> Self {
        assert!(port1 < 2048 && port2 < 2048);
        Self {
            rule_id,
            port: port1 | (port2 << 11),
            type_and_len: 0xc0 | (port2 >> 5) as u8,
            protocol_and_direction,
        }
    }

    pub fn make_stop() -> Self {
        Self {
            rule_id: RuleId::new(0, false),
            port: 0,
            type_and_len: 0b1011_1111,
            protocol_and_direction: 0,
        }
    }

    pub fn is_stop(&self) -> bool {
        self.type_and_len == 0b1011_1111
    }

    pub fn entry_type(&self) -> PortEntryType {
        use PortEntryType::*;
        if self.type_and_len == 0 {
            AnyPort
        } else if self.type_and_len & 0x80 == 0 {
            PortAndLength
        } else if self.type_and_len & 0xf0 == 0x80 {
            PortAndLength
        } else if self.type_and_len & 0xc0 == 0xc0 {
            TwoPorts
        } else {
            Stop
        }
    }

    // only valid for type BaseAndLength
    fn range_length(&self) -> u16 {
        match self.type_and_len >> 6 {
            0 => self.type_and_len as _,
            1 => (((self.type_and_len & 0x3f) + 1) as u16) << 6,
            2 => (((self.type_and_len & 0xf) + 1) as u16) << 12,
            _ => 0, // invalid
        }
    }

    fn two_ports(&self) -> (u16, u16) {
        let first_port = self.port & 0b0000_0111_1111_1111;
        let mut second_port = self.port & 0b1111_1000_0000_0000;
        second_port = (second_port >> 5) | (self.type_and_len & 0b0011_1111) as u16;
        (first_port, second_port)
    }

    pub fn matches(&self, port: Port, protocol_and_direction_mask: u8) -> bool {
        if (self.protocol_and_direction & protocol_and_direction_mask)
            != protocol_and_direction_mask
        {
            return false;
        }
        use PortEntryType::*;
        match self.entry_type() {
            AnyPort => true,
            PortAndLength => {
                let length = self.range_length();
                port >= self.port && port <= (self.port + length)
            }
            TwoPorts => {
                let (a, b) = self.two_ports();
                port == a || port == b
            }
            Stop => false, // should not happen
        }
    }
}

#[derive(Clone, Copy)]
pub struct PortTableReference(u16);
// low 10 bits: index in page
// high 6 bits: maximum length (at least 1), all bits set represents "indefinite"

impl PortTableReference {
    pub fn new(index: u16, len: u16) -> Self {
        if len == 0 {
            Self(0)
        } else {
            let len = (len - 1).min(63);
            Self((index & 0x3ff) | (len << 10))
        }
    }

    pub fn represents_no_match(&self) -> bool {
        self.0 == 0
    }

    pub fn index_from_page_start(&self) -> u16 {
        self.0 & 0x03ff
    }

    pub fn count(&self) -> u16 {
        let c = self.0 >> 10;
        if c == 0x3f { 512 } else { c + 1 }
    }
}

impl Debug for PortTableReference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = size_of::<PortTableEntry>();
        let index = self.index_from_page_start();
        f.write_fmt(format_args!(
            "offset 0x{:x} [{}], cnt={}",
            index as usize * s,
            index,
            self.count(),
        ))
    }
}

/// Types implementing BinaryEndpointTrait define the remote address part of a BinaryRule.
/// For a DNS name, this is the length and an offset into the page, for IP addresses it's
/// the address range (IPv4, because we have space in the padding) or just the address (IPv6).
pub trait BinaryEndpointTrait: Sized + Debug + 'static {
    type SearchTerm: 'static;

    // returns "greater" self is greater than search term
    fn compare(&self, search_term: &Self::SearchTerm, page: &RulePage<Self>) -> ExtOrder;

    // BinaryEndpoint can override
    fn min_match_len(&self) -> u8 {
        u8::MAX
    }
}

// implemented for name compare via `DomainNamePage` trait
impl ByteAtOffset for RulePage<NameBinaryEndpoint> {
    fn byte_at_offset(&self, offset: usize) -> u8 {
        // After other changes, the touch_usize() below seems to be no longer necessary.
        // touch_usize(&mut offset); // prevent optimization of range check below
        if offset >= BYTES_PER_RULE_PAGE {
            // return a different value for out-of-bounds than BpfName::byte_at_index() to
            // cause an early loop exit
            return 1;
        }
        let base = self as *const _ as usize;
        let ptr = (base + offset) as *const u8;
        unsafe { *ptr }
    }
}
impl DomainNamePage for RulePage<NameBinaryEndpoint> {}

#[cfg_attr(feature = "user", derive(Clone, Copy))]
#[repr(C)]
pub struct NameBinaryEndpoint {
    pub name_offset: u16, // offset into page in bytes from start
    pub name_len: u8,     // contrary to blocklists, we have space to encode the length here
    pub match_len: u8,    // full name_len is for sort order, but match_len determines equality
}
// We need match_len to continue a domain after a name in the ordered list. Example:
//   name in entry  match_len | comment
//-----------------+----------+------------------------------
//        obdev.at |      255 | host, implicitly added for domain
//   some-obdev.at |      255 | host sorted between obdev.at host and .obdev.at domain
//       .obdev.at |        9 | begin of domain
//   mail.obdev.at |      255 | host
// \1mail.obdev.at |        9 | continues domain obdev.at after host, but match limited to obdev.at
//       0obdev.at |      255 | example host after domain
//
// The name www.obdev.at does not match any entries. The binary search returns insertion point
// 0obdev.at and the domain match we consider is \1mail.obdev.at. The match length is at least
// 9, so we treat \1mail.obdev.at as domain match.
// Hosts have a match_len of 255, making it impossible to match due to this rule. However, a literal
// match is always returned as match, regardless of the match_len.

impl Debug for NameBinaryEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Name offset 0x{:x} len {} match_len {}",
            self.name_offset, self.name_len, self.match_len
        ))
    }
}

impl BinaryEndpointTrait for NameBinaryEndpoint {
    type SearchTerm = BpfString;

    fn compare(&self, search_term: &BpfString, page: &RulePage<Self>) -> ExtOrder {
        let start = self.name_offset as usize;
        let entry_byte_range = start..(start + self.name_len as usize);
        page.compare_domain_name(search_term, entry_byte_range, false).reverse()
    }

    fn min_match_len(&self) -> u8 {
        self.match_len
    }
}

#[cfg_attr(feature = "user", derive(Clone, Copy))]
#[derive(Debug)]
#[repr(C)]
pub struct Ipv4BinaryEndpoint {
    pub start_addr: u32, // in host byte order
    pub end_addr: u32,   // in host byte order, inclusive end
}

impl BinaryEndpointTrait for Ipv4BinaryEndpoint {
    type SearchTerm = u32;

    fn compare(&self, search_term: &u32, _page: &RulePage<Self>) -> ExtOrder {
        let bits = u32::from_be(*search_term);
        if self.end_addr < bits {
            ExtOrder::less(0)
        } else if self.start_addr > bits {
            ExtOrder::greater(0)
        } else {
            ExtOrder::equal()
        }
    }
}

#[cfg_attr(feature = "user", derive(Clone, Copy))]
#[derive(Debug)]
#[repr(C)]
pub struct Ipv6BinaryEndpoint {
    // An IPv6 block extends always up to the next entry, which can be a `represents_no_match()`
    // entry to end a block without beginning a new.
    pub start_addr: [u32; 4], // mixed byte order: u32 in host, index for net
}

impl BinaryEndpointTrait for Ipv6BinaryEndpoint {
    type SearchTerm = [u32; 4];

    fn compare(&self, search_term: &[u32; 4], _page: &RulePage<Self>) -> ExtOrder {
        for i in 0..4 {
            match self.start_addr[i].cmp(&u32::from_be(search_term[i])) {
                Ordering::Equal => {}
                other => return ExtOrder::from(other, 0),
            }
        }
        ExtOrder::equal()
    }

    fn min_match_len(&self) -> u8 {
        0
    }
}

impl BinaryEndpointTrait for () {
    type SearchTerm = ();

    fn compare(&self, _search_term: &(), _page: &RulePage<Self>) -> ExtOrder {
        ExtOrder::equal()
    }
}
