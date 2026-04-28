// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::StringId;

// We cannot make the DNS cache fully process-specific because many programs `fork()` after
// doing a lookup. We could make it executable-specific or even only specific on the
// executable of the parent process (if any). For the moment, we decide to make it completely
// global because this is the least complex solution.

#[repr(C)]
#[cfg_attr(feature = "user", derive(Clone, Copy))]
pub struct DnsNameKey {
    // Consider adding process identification here
    pub name: StringId,
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Clone, Copy))]
pub struct DnsIpv4Key {
    // Consider adding process identification here
    pub address: u32, // network byte order
}

#[repr(C)]
#[cfg_attr(feature = "user", derive(Clone, Copy))]
pub struct DnsIpv6Key {
    // Consider adding process identification here
    pub address: [u32; 4], // network byte order
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsNameKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsIpv4Key {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsIpv6Key {}
