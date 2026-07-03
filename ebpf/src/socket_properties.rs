// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{context::{ConcurrencyGroup, StaticBuffers}, current_executable::get_current_process_pair};
use aya_ebpf::{macros::map, maps::HashMap};
use common::flow_types::SocketProperties;

#[map]
static SOCKET_PROPERTIES: HashMap<u64, SocketProperties> = HashMap::with_max_entries(65536, 0);

/// registers socket if we can obtain a process pair
fn cache_current_process(cookie: u64, concurrency_group: ConcurrencyGroup) {
    if cookie == 0 {
        // not a valid cookie
        return;
    }
    let buffers = StaticBuffers::get(concurrency_group);
    if buffers.is_null() {
        return;
    }
    unsafe {
        let socket_properties = &mut (*buffers).socket_properties;
        // Since we ignore `process_pair` in case of failure, we don't need to initialize.
        if get_current_process_pair(&mut socket_properties.owner, buffers).is_some() {
            _ = SOCKET_PROPERTIES.insert(&cookie, socket_properties, 0);
        }
    }
}

pub fn socket_opened(cookie: u64) {
    cache_current_process(cookie, ConcurrencyGroup::CgroupSockCreate);
}

pub fn socket_closed(cookie: u64) {
    // We can remove the entry from `SOCKET_PROPERTIES` although it may still be used by active
    // flows because the flow has copied everything it needs from the SocketProperties. If
    // packets arrive for a flow after the socket was closed, they are associated with the
    // flow anyway. If the flow is closed as well, SocketProperties would not help us because
    // there will be no socket cookie for the packet.
    _ = SOCKET_PROPERTIES.remove(&cookie);
}

/// Obtains socket properties (including repsonsible process) from cache. If no cached entry is
/// found and `register_using_group` is `Some`, then it tries to create a new entry from the
/// current process. Since a buffer is needed for obtaining the current process, a concurrency
/// group for this buffer (matching the hooked function) must be given.
pub fn get_socket_properties(
    cookie: u64,
    register_using_group: Option<ConcurrencyGroup>,
) -> Option<&'static SocketProperties> {
    if cookie == 0 {
        None
    } else if let Some(props) = unsafe { SOCKET_PROPERTIES.get(&cookie) } {
        Some(props)
    } else if let Some(group) = register_using_group {
        cache_current_process(cookie, group);
        unsafe { SOCKET_PROPERTIES.get(&cookie) }
    } else {
        None
    }
}
