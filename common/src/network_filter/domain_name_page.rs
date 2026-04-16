// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    ByteAtOffset, DOMAIN_SEP,
    bpf_string::BpfString,
    ext_order::ExtOrder,
    repeat::{LoopReturn, repeat_closure},
};
use core::{cmp::Ordering, ops::Range};

/// This is a trait to be implemented by NameRulePage and NameBlocklistPage. It provides comparison
/// of names which are stored outside of list entries.
pub trait DomainNamePage: ByteAtOffset + Sized {
    /// Returns Ordering::Greater if search_term > entry, magnitude is length of substring match
    fn compare_domain_name(
        &self,
        search_term: &BpfString,
        entry_byte_range: Range<usize>,
        domain_compare: bool,
    ) -> ExtOrder {
        let entry_start = entry_byte_range.start;
        let mut entry_index = entry_byte_range.end;
        let mut search_term_index = search_term.len();
        let mut result = Ordering::Equal;
        repeat_closure(255, |_| {
            if search_term_index == 0 || entry_index <= entry_start {
                return LoopReturn::LoopBreak;
            }
            entry_index -= 1;
            search_term_index -= 1;
            let entry_byte = self.byte_at_offset(entry_index);
            let name_byte = search_term.byte_at_offset(search_term_index);
            let ord = name_byte.cmp(&entry_byte);
            if ord != Ordering::Equal {
                result = ord;
                return LoopReturn::LoopBreak;
            }
            LoopReturn::LoopContinue
        });
        let match_len = search_term.len() - search_term_index;
        if result != Ordering::Equal {
            return ExtOrder::from(result, match_len);
        }
        // All common elements compared equal so far. Check for domain match first:
        if domain_compare
            && search_term_index != 0
            && search_term.byte_at_offset(search_term_index - 1) == DOMAIN_SEP
        {
            ExtOrder::equal()
        } else if search_term_index != 0 {
            // entry did end before name, so name is greater:
            ExtOrder::greater(match_len)
        } else if entry_index != entry_start {
            // name did end before entry, so name is less
            ExtOrder::less(match_len)
        } else {
            // both strings are equal up to their end
            ExtOrder::equal()
        }
    }
}
