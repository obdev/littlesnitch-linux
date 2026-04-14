// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::flow_types::Verdict;
use core::cmp::Ordering;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Debug)]
pub struct RuleId(u32);
pub type RuleIndex = usize;

impl RuleId {
    pub const ANY: RuleId = RuleId(0);

    pub fn new(rule_index: RuleIndex, is_allow: bool) -> Self {
        Self(((rule_index as u32) << 1) + is_allow as u32)
    }

    pub fn rule_index(&self) -> RuleIndex {
        (self.0 >> 1) as _
    }

    pub fn low_precedence_with_verdict(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self((u32::MAX << 1) | 1),
            Verdict::Deny => Self(u32::MAX << 1),
        }
    }

    /// Whether this RuleId is a low_precedence_with_verdict() value.
    pub fn is_low_precedence(&self) -> bool {
        self.0 > u32::MAX - 4
    }

    pub fn verdict(&self) -> Verdict {
        match self.0 & 1 {
            0 => Verdict::Deny,
            _ => Verdict::Allow,
        }
    }

    // lower values mean more important
    pub fn precedence(&self) -> u32 {
        self.0
    }

    pub fn supersedes(&self, other: Self) -> bool {
        self.0 < other.0
    }

    pub fn higher_precedence(self, other: Self) -> RuleId {
        if self.supersedes(other) {
            self
        } else {
            other
        }
    }

    pub fn merge_higher_precedence(&mut self, other: Self) {
        if !self.supersedes(other) {
            *self = other
        }
    }
}

pub type ExePatternId = u16;

pub trait ExePatternIdExtension {
    fn any() -> ExePatternId;
    fn none() -> ExePatternId;
}
impl ExePatternIdExtension for ExePatternId {
    fn any() -> ExePatternId {
        0
    }
    fn none() -> ExePatternId {
        0xffff
    }
}

pub type Port = u16;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Protocol {
    Icmp = 0,
    Tcp = 1,
    Udp = 2,
    Sctp = 3,
    Other = 4,
}

impl Protocol {
    pub fn from_u8(raw_proto: u8) -> Protocol {
        match raw_proto {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmp,
            132 => Self::Sctp,
            _ => Self::Other,
        }
    }

    pub fn as_pattern(self) -> ProtocolPattern {
        ProtocolPattern(1u8 << self as u8)
    }
}

/// Bitmask for all protocols we support. `ProtocolPattern`s must have a defined sort order with
/// respect to each other. Comparison of protocols occurs only when exe_pattern and endpoint match.
/// Due to the requirement of non-overlapping sortable ranges, we could use a protocol range
/// without sacrificing generality. A bitmap seems easier to handle in one byte, though.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProtocolPattern(u8);

impl ProtocolPattern {
    pub const fn any() -> Self {
        Self((1u8 << (Protocol::Other as u8 + 1)) - 1)
    }

    pub const fn none() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn contains(&self, protocol: Protocol) -> bool {
        self.contains_raw(protocol as u8)
    }

    pub const fn contains_raw(&self, protocol: u8) -> bool {
        self.0 & (1 << protocol) != 0
    }

    pub const fn start(self) -> ProtocolPattern {
        let x = self.0 as i8;
        // clears all bits except the least significant 1 bit of the input.
        // E.g.: 0b101010 becomes 0b000010.
        ProtocolPattern((x & -x) as u8)
    }

    pub const fn inclusive_end(self) -> ProtocolPattern {
        let mut x = self.0 as u16;
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        ProtocolPattern(((x + 1) >> 1) as u8)
    }

    pub const fn hull_range(self) -> ProtocolPattern {
        let mut x = self.0;
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        let y = self.0 as i8;
        ProtocolPattern(x & (y & -y) as u8)
    }

    pub const fn intersection(self, other: ProtocolPattern) -> ProtocolPattern {
        ProtocolPattern(self.0 & other.0)
    }

    pub const fn union(&self, other: ProtocolPattern) -> ProtocolPattern {
        ProtocolPattern(self.0 | other.0)
    }

    pub const fn cmp(self, other: Self) -> Ordering {
        if (self.0 & other.0) != 0 {
            Ordering::Equal
        } else if self.0 > other.0 {
            Ordering::Greater
        } else {
            Ordering::Less
        }
    }

    // compare only the start of a protocol range
    pub fn cmp_start(self, other: Self) -> Ordering {
        self.start().0.cmp(&other.start().0)
    }

    /// number of protocols included in pattern
    pub fn count(&self) -> usize {
        self.0.count_ones() as _
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct DirectionPattern(u8);

impl Default for DirectionPattern {
    fn default() -> Self {
        Self::BOTH
    }
}

impl DirectionPattern {
    pub const OUTBOUND: DirectionPattern = Self(1);
    pub const INBOUND: DirectionPattern = Self(2);
    pub const BOTH: DirectionPattern = Self::OUTBOUND.union(Self::INBOUND);
    pub const NONE: DirectionPattern = Self(0);

    pub fn with_inbound(is_inbound: bool) -> Self {
        if is_inbound {
            Self::INBOUND
        } else {
            Self::OUTBOUND
        }
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn count(self) -> usize {
        ((self.0 & 1) + (self.0 >> 1)) as _
    }
}
