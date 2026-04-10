// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

pub mod bitset;
pub mod bpf_string;
pub mod closed_range;
pub mod dns_types;
pub mod event;
pub mod ext_order;
pub mod flow_debug;
pub mod flow_types;
mod mock_node_cache;
mod mock_strings_cache;
pub mod network_filter;
pub mod node_cache;
pub mod repeat;

use bitset::BitSet;
use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Deref, DerefMut, Sub, SubAssign},
};

// We use the 0-byte internally as domain separator. This makes domain matching in blocklists
// and rules easier.
pub const DOMAIN_SEP: u8 = b'\0';

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
pub struct StringId(pub u64);

impl StringId {
    pub const fn none() -> StringId {
        StringId(0)
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct NanoTime(pub i64); // signed to allow differences

impl Add for NanoTime {
    type Output = NanoTime;

    fn add(self, rhs: Self) -> Self::Output {
        NanoTime(self.0 + rhs.0)
    }
}

impl AddAssign for NanoTime {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl Sub for NanoTime {
    type Output = NanoTime;

    fn sub(self, rhs: Self) -> Self::Output {
        NanoTime(self.0 - rhs.0)
    }
}

impl SubAssign for NanoTime {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

#[repr(C)]
#[derive(PartialEq, Eq, Default, Clone, Copy)]
pub struct NodeFeatures(pub BitSet);

impl Deref for NanoTime {
    type Target = i64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for NodeFeatures {
    type Target = BitSet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NodeFeatures {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NodeFeatures {
    // When we iterate the parent chain and reach an App Manager, we can abort. There are no
    // valid parent processes (for "parent via process" connections) from there on. App managers
    // are e.g. systemd, gnome-shell and similar processes responsible for launching UI apps.
    pub const APP_MANAGER: BitSet = BitSet::from_raw(1 << 0);

    // When we iterate the parent chain, we should ignore Non-Parents. These are processes which
    // are of little intertest to the user (e.g. shells).
    pub const NON_PARENT: BitSet = BitSet::from_raw(1 << 1);
}

pub trait ByteAtOffset {
    fn byte_at_offset(&self, index: usize) -> u8;
}

// The `touch_*()` functions below are no-ops, but the compiler does not know. They are made
// to prevent optimization when the compiler knows that a value is in a particular range and
// strips off range checks, but the eBPF verifier does not know and requires the range check.
#[inline(always)]
pub fn touch_usize(_v: &mut usize) {
    #[cfg(target_arch = "bpf")]
    unsafe {
        core::arch::asm!("; {i} = {i}", i = inout(reg) * _v,);
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for StringId {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NanoTime {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NodeFeatures {}
