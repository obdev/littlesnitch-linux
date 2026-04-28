// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    NanoTime, StringId,
    network_filter::{blocklist_page::BlocklistMatch, rule_types::RuleId},
    node_cache::NodeId,
};
use core::{
    mem::transmute,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[cfg(feature = "user")]
use core::hash::Hash;

// constants in network byte order:
pub const LOCALHOST_ADDRESS: u32 = 0x7f00_0000_u32.to_be(); // 127.0.0.0
pub const LOCALHOST_MASK: u32 = 0xff00_0000_u32.to_be(); // 255.0.0.0

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "user", derive(Copy, Hash))]
pub struct FlowIdentifier {
    pub protocol: u32, // u8 wold be sufficient, but avoid padding for byte-wise equality
    pub local_address: IpAddress,
    pub remote_address: IpAddress,
    pub local_port: u16,
    pub remote_port: u16,
}

impl FlowIdentifier {
    pub fn public_port(&self, is_inbound: bool) -> u16 {
        if is_inbound {
            self.local_port
        } else {
            self.remote_port
        }
    }

    pub fn private_port(&self, is_inbound: bool) -> u16 {
        if is_inbound {
            self.remote_port
        } else {
            self.local_port
        }
    }
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Clone, Copy))]
pub struct FlowProperties {
    pub process_pair: ProcessPair,
    pub remote_name: StringId,
    pub socket_cookie: u64,
    pub last_activity: NanoTime,
    pub is_inbound: bool,
    pub is_closed: bool,
    pub verdict: Verdict,
    pub reason: VerdictReason,
    pub ruleset_generation: u64,    // for validating cached verdict
}

pub struct ConnectionIdentifierRef<'a> {
    pub process_pair: &'a ProcessPair,
    pub remote_address: &'a IpAddress,
    pub remote_name: StringId,
    pub is_inbound: bool,
    pub protocol: u8,
    pub port: u16, // remote port for outbound, local port for inbound
}

#[repr(C)]
#[derive(Clone)]
#[cfg_attr(feature = "user", derive(Copy))]
pub struct SocketProperties {
    pub owner: ProcessPair,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Allow,
    Deny,
}

#[repr(C)]
#[derive(Clone, Debug)]
#[cfg_attr(feature = "user", derive(Copy))]
pub enum VerdictReason {
    NotYetDetermined,
    DefaultAction,
    NameBlocklist(BlocklistMatch),
    Ipv4Blocklist(BlocklistMatch),
    Ipv6Blocklist(BlocklistMatch),
    Rule(RuleId),
    Other,
}

#[repr(C)]
#[derive(Default, Clone)]
#[cfg_attr(feature = "user", derive(Copy))]
pub struct ProcessPair {
    pub pid: i32,
    pub parent_pid: i32,
    pub executable_pair: ExecutablePair,
}

impl ProcessPair {
    pub fn is_known(&self) -> bool {
        self.executable_pair.is_known()
    }
}

impl PartialEq for ProcessPair {
    fn eq(&self, other: &Self) -> bool {
        if self.executable_pair != other.executable_pair {
            return false;
        }
        if self.executable_pair.connecting.is_some() && self.pid != other.pid {
            return false;
        }
        if self.executable_pair.parent.is_some() && self.parent_pid != other.parent_pid {
            return false;
        }
        return true;
    }
}

impl Eq for ProcessPair {}

#[cfg(feature = "user")]
impl Hash for ProcessPair {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.executable_pair.hash(state);
        if self.executable_pair.connecting.is_some() {
            self.pid.hash(state);
        }
        if self.executable_pair.parent.is_some() {
            self.parent_pid.hash(state);
        }
    }
}

#[repr(C)]
#[derive(Default, Clone)]
#[cfg_attr(feature = "user", derive(Copy))]
pub struct ExecutablePair {
    // We use separate booleans instead of making the `FileNode`s optional. This saves
    // two u64 space due to padding. We could provide a function-based API to abstract
    // this decision, but it's hard to design an API which does not cause block copies
    // for access. We therefore expose our struct fields.
    pub connecting: Option<NodeId>,
    pub parent: Option<NodeId>,
    pub uid: u32,
}

impl ExecutablePair {
    pub fn is_known(&self) -> bool {
        self.connecting.is_some()
    }
}

impl PartialEq for ExecutablePair {
    fn eq(&self, other: &Self) -> bool {
        if self.connecting != other.connecting || self.parent != other.parent {
            return false;
        }
        if self.connecting.is_some() && self.uid != other.uid {
            return false;
        }
        return true;
    }
}

impl Eq for ExecutablePair {}

#[cfg(feature = "user")]
impl Hash for ExecutablePair {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.connecting.hash(state);
        self.parent.hash(state);
        if self.connecting.is_some() {
            self.uid.hash(state);
        }
    }
}

// Avoid using an enum for IpAddress because it would leave parts of the raw data uninitialized.
// The eBPF verifier does not like that.
#[repr(C)]
#[derive(Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "user", derive(Copy, Hash))]
pub struct IpAddress {
    pub(crate) is_v6: bool,
    _padding: [u8; 3],
    pub(crate) address: [u32; 4],
}

impl IpAddress {
    // address in network byte order
    pub fn v4(address: u32) -> Self {
        Self {
            is_v6: false,
            address: [address, 0, 0, 0],
            ..Default::default() // ensure that padding is set to 0
        }
    }

    // address in network byte order (transmute from struct in6_addr)
    pub fn v6(address: [u32; 4]) -> Self {
        Self {
            is_v6: true,
            address,
            ..Default::default() // ensure that padding is set to 0
        }
    }

    #[inline]
    pub fn address(&self) -> &[u32; 4] {
        &self.address
    }

    #[inline]
    pub fn is_v6(&self) -> bool {
        self.is_v6
    }

    pub fn is_localhost(&self) -> bool {
        if self.is_v6 {
            self.address[0] == 0
                && self.address[1] == 0
                && self.address[2] == 0
                && self.address[3] == 1u32.to_be()
        } else {
            (self.address[0] & LOCALHOST_MASK) == LOCALHOST_ADDRESS
        }
    }

    pub fn core_ip_addr(&self) -> IpAddr {
        if self.is_v6 {
            let a: [u8; 16] = unsafe { transmute(self.address) };
            IpAddr::V6(Ipv6Addr::from(a))
        } else {
            IpAddr::V4(Ipv4Addr::from(u32::from_be(self.address[0])))
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpAddress {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowIdentifier {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowProperties {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SocketProperties {}
