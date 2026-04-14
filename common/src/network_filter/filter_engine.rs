// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    bpf_string::BpfString,
    flow_types::VerdictReason,
    network_filter::{
        binary_rule::PortTableEntry,
        blocklist_matching::{blocklist_ipv4_match, blocklist_ipv6_match, blocklist_name_match},
        filter_model::{FilterMetainfo, FilterModel},
        port_table_search::{PortTableSearchTerm, SearchSpecification, SearchTableType},
        rule_page::*,
        rule_types::{DirectionPattern, ExePatternId, ExePatternIdExtension, Protocol},
    },
};

impl<T: FilterModel + Sized> FilterEngine for T {}

/// This type represents an input to the network filter. Most fields are self-explanatory,
/// except `get_exe_pattern_ids()`. The filter engine represents executable pairs by identifier.
/// Rules use executable patterns, which are basically glob patterns, to reference executables.
/// The kernel, on the other hand, uses `NodeId`s to reference concrete executables (disk files).
/// Since we cannot implement a complex matching algorithm in eBPF, we map to `ExePatternId`s
/// as follows:
/// Each executable pair pattern in a rule is mapped to a unique ID, the `ExePatternId`. This ID
/// is assigned during compiling into `CompiledRules`. Then, each executable pair pattern is
/// resolved to all executable paths it matches. These paths are converted to `NodeId`s and a
/// second map table maps pairs of `NodeId`s to `ExePatternId`s. So there are two unidirectional
/// mappings:
/// executable pair pattern -> ExePatternId
/// NodeId pair -> ExePatternId
/// The matching can now be performed in the kernel by just comparing `ExePatternId`s.
/// The conversion from a pair of `NodeId`s or whatever executable representation is used to
/// an `ExePatternId` must be done by the type implementing `FilterEngineInput`. There are up
/// to 3 `ExePatternId`s to take into account: `ExePatternId::any()` to look for rules without
/// a specific process, the ID for the primary executable only (matching all via executables
/// implicitly) and the ID for the pair primary and via executable. If there is no `exe_pattern_id`
/// for a given executable, it must be omitted from the result. It means that none of the
/// specific rules can match.
pub trait FilterEngineInput {
    /// Returns the number of exe_pattern_ids actually used.
    fn get_exe_pattern_ids(&self, exe_pattern_ids: &mut [ExePatternId; 3]) -> usize;
    fn process_owner_uid(&self) -> u32; // not currently used
    fn remote_name(&self) -> Option<&BpfString>;
    fn is_ipv6_address(&self) -> bool;
    fn ipv4_address(&self) -> u32; // in network byte order
    fn ipv6_address(&self) -> &[u32; 4]; // in network byte order
    fn is_inbound(&self) -> bool;
    fn protocol(&self) -> u8;
    fn port(&self) -> u16;
}

pub trait FilterEngine: FilterModel + Sized {
    /// This is the central entry point for the filter engine. It allows customization in the
    /// following ways: (a) the filter can be applied to any type which can provide the information
    /// defined by the `FilterEngineInput` trait, and (b) a `search_spec`, which is any type
    /// implementing the `SearchSpecification` trait, defines how the port table part of rules
    /// is searched and how results from various tables are combined.
    fn evaluate_network_filter<S: SearchSpecification, Input: FilterEngineInput>(
        &self,
        connection: &Input,
        search_spec: &mut S,
    ) {
        let meta = match self.metainfo() {
            Some(meta) => meta,
            None => return,
        };
        if connection.is_ipv6_address() {
            if let Some(blocklist_match) = blocklist_ipv6_match(self, connection.ipv6_address()) {
                search_spec.set_blocklist_match(
                    meta.ip_blocklist_rule_id,
                    VerdictReason::Ipv6Blocklist(blocklist_match),
                );
            }
        } else {
            if let Some(blocklist_match) = blocklist_ipv4_match(self, connection.ipv4_address()) {
                search_spec.set_blocklist_match(
                    meta.ip_blocklist_rule_id,
                    VerdictReason::Ipv4Blocklist(blocklist_match),
                );
            }
        }
        if let Some(remote_name) = connection.remote_name() {
            let rule_id = meta.name_blocklist_rule_id;
            if rule_id.supersedes(search_spec.benchmark_rule_id())
                && let Some(blocklist_match) = blocklist_name_match(self, remote_name)
            {
                search_spec
                    .set_blocklist_match(rule_id, VerdictReason::NameBlocklist(blocklist_match));
            }
        }
        let mut exe_pattern_ids = [ExePatternId::none(); 3];
        connection.get_exe_pattern_ids(&mut exe_pattern_ids);
        self.evaluate_rules(meta, connection, exe_pattern_ids[0], search_spec);
        self.evaluate_rules(meta, connection, exe_pattern_ids[1], search_spec);
        self.evaluate_rules(meta, connection, exe_pattern_ids[2], search_spec);
    }

    /// Given a particular `exe_pattern_id`, evaluate rules matching the executable and
    /// connection.
    #[inline(never)]
    fn evaluate_rules<S: SearchSpecification, Input: FilterEngineInput>(
        &self,
        meta: &FilterMetainfo,
        connection: &Input,
        exe_pattern_id: ExePatternId,
        search_spec: &mut S,
    ) {
        if exe_pattern_id == ExePatternId::none() {
            return;
        }
        let common_search = PortTableSearchTerm {
            port: connection.port(),
            protocol_and_direction: PortTableEntry::protocol_and_direction(
                DirectionPattern::with_inbound(connection.is_inbound()),
                Protocol::from_u8(connection.protocol()).as_pattern(),
            ),
        };
        if connection.is_ipv6_address() {
            if let Some((page_base, port_table_ref)) = Ipv6RulePage::find_matching_port_table(
                self.ipv6_rules(),
                meta.ipv6_rules.page_count,
                exe_pattern_id,
                connection.ipv6_address(),
            ) {
                search_spec.search_port_table(
                    SearchTableType::Ipv6,
                    page_base,
                    port_table_ref,
                    &common_search,
                );
            }
        } else {
            if let Some((page_base, port_table_ref)) = Ipv4RulePage::find_matching_port_table(
                self.ipv4_rules(),
                meta.ipv4_rules.page_count,
                exe_pattern_id,
                &connection.ipv4_address(),
            ) {
                search_spec.search_port_table(
                    SearchTableType::Ipv4,
                    page_base,
                    port_table_ref,
                    &common_search,
                );
            }
        }

        if let Some(remote_name) = connection.remote_name() {
            if let Some((page_base, port_table_ref)) = NameRulePage::find_matching_port_table(
                self.name_rules(),
                meta.name_rules.page_count,
                exe_pattern_id,
                remote_name,
            ) {
                search_spec.search_port_table(
                    SearchTableType::Name,
                    page_base,
                    port_table_ref,
                    &common_search,
                );
            }
        }
        if let Some((page_base, port_table_ref)) = AnyEndpointRulePage::find_matching_port_table(
            self.any_endpoint_rules(),
            meta.any_endpoint_rules.page_count,
            exe_pattern_id,
            &(),
        ) {
            search_spec.search_port_table(
                SearchTableType::AnyEndpoint,
                page_base,
                port_table_ref,
                &common_search,
            );
        }
    }
}
