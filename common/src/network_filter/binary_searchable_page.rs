// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    ext_order::ExtOrder,
    network_filter::filter_model::FilterTable,
    repeat::{LoopReturn, repeat},
};
use core::ops::Range;

pub trait BinarySearchablePage: Sized {
    type SearchTerm<'a>;

    fn entry_count(&self) -> u16;

    /// Returns`Ordering::Greater` when search term > entry. In case of a failed match, the
    /// mangnitude relative to the entry below the insertion point is passed up in the result
    /// of the binary search.
    fn compare(&self, search_term: &Self::SearchTerm<'_>, entry_index: u16) -> ExtOrder;

    // Returns the matching page plus the page index
    fn search_for_page<'a, 'b, Map: FilterTable<Self>>(
        search_term: &'b Self::SearchTerm<'b>,
        map: &'a Map,
        page_count: u32,
    ) -> Option<(&'a Self, u32)> {
        let mut context = SearchPageContext {
            map,
            index_range: 0..page_count,
            search_term,
            matching_page: None,
        };
        // 16 steps can search in 64k pages
        repeat(32, search_for_page_inner, &mut context);
        if let Some(page) = context.matching_page {
            Some((page, context.index_range.start - 1))
        } else {
            None // all first entries of pages were greater than search term
        }
    }

    /// Returns a tuple `(match_len, match_candidate_index)`. `match_len` indicates how many bytes
    /// of the search term did match the entry. For an exact match, u8::MAX is returned, regardless
    /// of the real match lenght (which is always the search term length). Compare with u8::MAX to
    /// know whether the match is exact.
    /// The match candidate is the index of the matching entry if a match is found, or the entry
    /// before the insertion point otherwise. When comparing by IP block start, this is the
    /// block potentially matching the result. For names, this is the potential domain match.
    fn search_in_page<'a>(
        &'a self,
        search_term: &'a Self::SearchTerm<'a>,
        entry_count: u16,
    ) -> (u8, u16) {
        let mut context = SearchInPageContext {
            index_range: 0..entry_count,
            match_len: 0,
            search_term,
            page: self,
        };
        // 10 steps can search in 1k entries
        repeat(16, search_in_page_inner, &mut context);
        if context.match_len == u8::MAX {
            (context.match_len, context.index_range.start)
        } else if context.index_range.start == 0 {
            // A match would be in the previous page. Since we are searching this page, this must
            // be the first page and we have no match, not even a suffix match with a previous
            // entry.
            (0, 0)
        } else {
            // If we have no match, the search returns the insertion point. This is the index of
            // the next entry which is *greater* than our search term. Since we use this for
            // IP blocklist matches, we want to round down to the start address of a range.
            (context.match_len, context.index_range.start - 1)
        }
    }
}

struct SearchPageContext<'a, 'b, Map: FilterTable<Page>, Page: BinarySearchablePage + 'a> {
    pub map: &'a Map,
    pub index_range: Range<u32>,
    pub search_term: &'b <Page as BinarySearchablePage>::SearchTerm<'b>,
    pub matching_page: Option<&'a Page>,
}

extern "C" fn search_for_page_inner<Map: FilterTable<Page>, Page: BinarySearchablePage>(
    _index: u64,
    context: &mut SearchPageContext<Map, Page>,
) -> LoopReturn {
    if context.index_range.end <= context.index_range.start {
        return LoopReturn::LoopBreak;
    }
    let mid_index = (context.index_range.start + context.index_range.end) / 2;
    if let Some(page) = context.map.get(mid_index) {
        let ext_order = page.compare(context.search_term, 0);
        // We don't care about the match length at this point, we're just identifying the page.
        if ext_order.is_less() {
            // search_term < page
            context.index_range.end = mid_index;
        } else if ext_order.is_greater() {
            // search_term > page
            // The last compared page with start < search_term is our result
            context.matching_page = Some(page);
            context.index_range.start = mid_index + 1
        } else {
            // exact match, no matter whether domain or host
            context.matching_page = Some(page);
            // When a page is set, `index_range.start` points alreay to the next page
            context.index_range.start = mid_index + 1;
            return LoopReturn::LoopBreak;
        }
    } else {
        return LoopReturn::LoopBreak; // should not happen, error obtaining page
    }
    LoopReturn::LoopContinue
}

struct SearchInPageContext<'a, Page: BinarySearchablePage> {
    pub index_range: Range<u16>,
    pub match_len: u8,
    pub search_term: &'a <Page as BinarySearchablePage>::SearchTerm<'a>,
    pub page: &'a Page,
}

extern "C" fn search_in_page_inner<Page: BinarySearchablePage>(
    _index: u64,
    context: &mut SearchInPageContext<Page>,
) -> LoopReturn {
    if context.index_range.end <= context.index_range.start {
        return LoopReturn::LoopBreak;
    }
    let mid_index = (context.index_range.start + context.index_range.end) / 2;
    let ext_order = context.page.compare(context.search_term, mid_index);
    if ext_order.is_less() {
        // search_term < entry
        context.index_range.end = mid_index;
    } else if ext_order.is_greater() {
        // search_term > entry
        context.index_range.start = mid_index + 1;
        // If no exact match is found, the last compare returning Ordering::Less was with the
        // "match candidate".
        context.match_len = ext_order.magnitude() as _;
    } else {
        context.index_range.start = mid_index; // this is where we have found the result
        context.match_len = u8::MAX;
        return LoopReturn::LoopBreak;
    }
    LoopReturn::LoopContinue
}
