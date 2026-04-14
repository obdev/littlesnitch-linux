// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{kernel_filter_model::EXE_PATTERNS, strings_cache::string_for_identifier};
use common::{
    bpf_string::BpfString,
    event::ConnectionIdentifier,
    network_filter::{
        filter_engine::FilterEngineInput,
        rule_page::ExeNodePair,
        rule_types::{ExePatternId, ExePatternIdExtension},
    },
};
use core::mem::transmute;

/// This Newtype wraps the foreign `ConnectionIdentifier` so that we can implement the foreign
/// `FilterEngineInput` trait for it.
pub struct FilterEngineConnection(ConnectionIdentifier);

impl FilterEngineConnection {
    /// References to `ConnectionIdentifier` and `FilterEngineConnection` are interchangeable
    /// as far as memory layout is concerned. Use if we just need the type which implements the
    /// `FilterEngineInput` trait but only have `ConnectionIdentifier`.
    pub fn wrap(connection_identifier: &ConnectionIdentifier) -> &Self {
        unsafe { transmute(connection_identifier) }
    }
}

impl FilterEngineInput for FilterEngineConnection {
    #[inline(always)]
    fn get_exe_pattern_ids(&self, exe_pattern_ids: &mut [ExePatternId; 3]) -> usize {
        let executable_pair = &self.0.process_pair.executable_pair;
        exe_pattern_ids[0] = ExePatternId::any();
        let mut index = 1;
        if let Some(connecting) = executable_pair.connecting {
            if let Some(parent) = executable_pair.parent {
                let exe_pattern = ExeNodePair { primary: parent, via: Some(connecting) };
                if let Some(id) = unsafe { EXE_PATTERNS.get(&exe_pattern) } {
                    exe_pattern_ids[index] = *id;
                    index += 1;
                }
                let exe_pattern = ExeNodePair { primary: parent, via: None };
                if let Some(id) = unsafe { EXE_PATTERNS.get(&exe_pattern) } {
                    exe_pattern_ids[index] = *id;
                    index += 1;
                }
            } else {
                let exe_pattern = ExeNodePair { primary: connecting, via: None };
                if let Some(id) = unsafe { EXE_PATTERNS.get(&exe_pattern) } {
                    exe_pattern_ids[index] = *id;
                    index += 1;
                }
            }
        }
        index
    }

    #[inline(always)]
    fn process_owner_uid(&self) -> u32 {
        self.0.process_pair.executable_pair.uid
    }

    #[inline(always)]
    fn remote_name(&self) -> Option<&BpfString> {
        string_for_identifier(self.0.remote_name)
    }

    #[inline(always)]
    fn is_ipv6_address(&self) -> bool {
        self.0.remote_address.is_v6()
    }

    #[inline(always)]
    fn ipv4_address(&self) -> u32 {
        self.0.remote_address.address()[0]
    }

    #[inline(always)]
    fn ipv6_address(&self) -> &[u32; 4] {
        self.0.remote_address.address()
    }

    #[inline(always)]
    fn is_inbound(&self) -> bool {
        self.0.is_inbound
    }

    #[inline(always)]
    fn protocol(&self) -> u8 {
        self.0.protocol
    }

    #[inline(always)]
    fn port(&self) -> u16 {
        self.0.port
    }
}
