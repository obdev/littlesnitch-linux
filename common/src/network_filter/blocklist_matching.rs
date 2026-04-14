// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    ByteAtOffset,
    bpf_string::BpfString,
    ext_order::ExtOrder,
    network_filter::{
        binary_searchable_page::BinarySearchablePage, blocklist_page::*,
        domain_name_page::DomainNamePage, filter_model::FilterModel,
    },
    touch_usize,
};

use core::mem::transmute_copy;

pub fn blocklist_name_match(
    filter_model: &impl FilterModel,
    name: &BpfString,
) -> Option<BlocklistMatch> {
    let meta = filter_model.metainfo()?;
    let page_count = meta.name_blocklist.page_count;
    if let Some((page, page_index)) =
        NameBlocklistPage::search_for_page(name, filter_model.name_blocklist(), page_count)
        && let (match_len, entry_index) = page.search_in_page(name, page.entry_count())
        && match_len == u8::MAX
    {
        Some(BlocklistMatch {
            page_index,
            entry_index,
            generation: meta.name_blocklist.generation,
        })
    } else {
        None
    }
}

pub fn blocklist_ipv4_match(
    filter_model: &impl FilterModel,
    address: u32,
) -> Option<BlocklistMatch> {
    let address = u32::from_be(address); // we work with host byte order for faster compare
    let meta = filter_model.metainfo()?;
    let page_count = meta.ipv4_blocklist.page_count;
    if let Some((page, page_index)) =
        Ipv4BlocklistPage::search_for_page(&address, filter_model.ipv4_blocklist(), page_count)
    {
        let page_entry_count = if page_index + 1 == page_count {
            meta.ipv4_blocklist.last_page_entry_count
        } else {
            IPV4_BLOCKLIST_PAGE_ENTRY_COUNT as u16
        };
        let (_, entry_index) = page.search_in_page(&address, page_entry_count);
        if (entry_index & 1) == 0 {
            return Some(BlocklistMatch {
                page_index,
                entry_index,
                generation: meta.ipv4_blocklist.generation,
            });
        }
    }
    None
}

pub fn blocklist_ipv6_match(
    filter_model: &impl FilterModel,
    address: &[u32; 4],
) -> Option<BlocklistMatch> {
    let meta = filter_model.metainfo()?;
    let address: u128 = unsafe { transmute_copy(address) };
    let address = u128::from_be(address); // we work with host byte order for faster compare
    let page_count = meta.ipv6_blocklist.page_count;
    if let Some((page, page_index)) =
        Ipv6BlocklistPage::search_for_page(&address, filter_model.ipv6_blocklist(), page_count)
    {
        let page_entry_count = if page_index + 1 == page_count {
            meta.ipv6_blocklist.last_page_entry_count
        } else {
            IPV6_BLOCKLIST_PAGE_ENTRY_COUNT as u16
        };
        let (_, entry_index) = page.search_in_page(&address, page_entry_count);
        if (entry_index & 1) == 0 {
            return Some(BlocklistMatch {
                page_index,
                entry_index,
                generation: meta.ipv6_blocklist.generation,
            });
        }
    }
    None
}

impl DomainNamePage for NameBlocklistPage {}

impl BinarySearchablePage for NameBlocklistPage {
    type SearchTerm<'a> = BpfString;

    fn entry_count(&self) -> u16 {
        self.entry_count
    }

    fn compare(&self, name: &BpfString, entry_index: u16) -> ExtOrder {
        let entry = self.entry_at_index(entry_index);
        self.compare_domain_name(name, entry.0, entry.1)
    }
}

impl BinarySearchablePage for Ipv4BlocklistPage {
    type SearchTerm<'a> = u32;

    fn entry_count(&self) -> u16 {
        self.entries.len() as _
    }

    fn compare(&self, address: &u32, entry_index: u16) -> ExtOrder {
        let mut index = entry_index as usize;
        touch_usize(&mut index); // prevent compiler from removing the bounds check
        // we must not rely on the Rust bounds check because the analyzer can't handle panics
        if index >= self.entries.len() {
            return ExtOrder::greater(0);
        }
        ExtOrder::from(address.cmp(&self.entries[index]), 0)
    }
}

impl BinarySearchablePage for Ipv6BlocklistPage {
    type SearchTerm<'a> = u128;

    fn entry_count(&self) -> u16 {
        self.entries.len() as _
    }

    fn compare(&self, address: &u128, entry_index: u16) -> ExtOrder {
        let mut index = entry_index as usize;
        touch_usize(&mut index); // prevent compiler from removing the bounds check
        let entry = if index < self.entries.len() {
            &self.entries[index]
        } else {
            &self.entries[0]
        };
        ExtOrder::from(address.cmp(entry), 0)
    }
}

// In order to extend BlocklistPage here, we must make a trait:

impl ByteAtOffset for NameBlocklistPage {
    fn byte_at_offset(&self, index: usize) -> u8 {
        // After other changes, the touch_usize() below seems to be no longer necessary.
        // touch_usize(&mut index); // prevent optimization of range check below
        if index >= BYTES_PER_BLOCKLIST_PAGE {
            // return a different value for out-of-bounds than BpfName::byte_at_index() to
            // cause an early loop exit
            return 1;
        }
        let base = self as *const _ as usize;
        let ptr = (base + index) as *const u8;
        unsafe { *ptr }
    }
}

// ─────────────────────────────────────────────────────────────────────
//   Test module
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::{
        DOMAIN_SEP,
        network_filter::{filter_model::FilterTable, mock_filter_model::MockFilterModel},
    };

    use super::*;
    use std::{ptr, slice::from_raw_parts};

    #[test]
    fn test_simple_name() {
        let mut raw_page = RawPage::new();
        raw_page.push_name(b"www.google.com", false);
        raw_page.push_name(b"orf.at", true);
        let page = raw_page.emit_page();
        print_page(&page);
        let model = MockFilterModel::new();
        model.name_blocklist().set_pages(vec![page]);
        assert!(
            blocklist_name_match(&model, &BpfString::from_str_bytes(b"www.google.com")).is_some()
        );
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"test.orf.at")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"orf.at")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"google.com")).is_some());
        assert!(
            !blocklist_name_match(&model, &BpfString::from_str_bytes(b"www.obdev.at")).is_some()
        );
    }

    #[test]
    fn test_domain_matching() {
        let mut raw_page = RawPage::new();
        let mut names = [b"xxa.com", b"xxb.com", b"xxc.com", b"xxd.com", b"xxe.com"];
        names.sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
        for name in names {
            raw_page.push_name(name, true);
        }
        let page = raw_page.emit_page();
        print_page(&page);
        let model = MockFilterModel::new();
        model.name_blocklist().set_pages(vec![page]);
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"a.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"b.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"c.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"d.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"e.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"xxa.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"xxb.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"xxc.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"xxd.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"xxe.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"zxxa.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"zxxb.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"zxxc.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"zxxd.com")).is_some());
        assert!(!blocklist_name_match(&model, &BpfString::from_str_bytes(b"zxxe.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"www.xxa.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"www.xxb.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"www.xxc.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"www.xxd.com")).is_some());
        assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(b"www.xxe.com")).is_some());
    }

    #[test]
    fn test_multi_pages() {
        let mut raw_page = RawPage::new();
        let mut names = [
            b"1a.com", b"2a.com", b"3a.com", b"1b.com", b"2b.com", b"3b.com", b"1c.com", b"2c.com",
            b"3c.com", b"1d.com", b"2d.com", b"3d.com", b"1e.com", b"2e.com", b"3e.com",
        ];
        names.sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
        let mut pages = Vec::<NameBlocklistPage>::new();
        for page_index in 0..5 {
            for name_index in 0..3 {
                raw_page.push_name(names[3 * page_index + name_index], false);
            }
            pages.push(raw_page.emit_page());
        }
        let model = MockFilterModel::new();
        (model.name_blocklist()).set_pages(pages);
        for name in names {
            assert!(blocklist_name_match(&model, &BpfString::from_str_bytes(name)).is_some());
        }
    }

    #[test]
    fn test_doubleclick_domain_search_edge_case() {
        let mut raw_page = RawPage::new();
        let mut names: [&[u8]; 6] = [
            b"a.doubleclick.net" as &[u8],
            b"ff.doubleclick.net" as &[u8],
            b"g.doubleclick.net" as &[u8],
            b"ad-g.doubleclick.net" as &[u8],
            b"h.doubleclick.net" as &[u8],
            b"z.doubleclick.net" as &[u8],
        ];
        names.sort_by(|a, b| a.iter().rev().cmp(b.iter().rev()));
        for name in names {
            raw_page.push_name(name, true);
        }
        let page = raw_page.emit_page();
        print_page(&page);

        let model = MockFilterModel::new();
        model.name_blocklist().set_pages(vec![page]);

        assert!(
            blocklist_name_match(&model, &BpfString::from_str_bytes(b"ff.doubleclick.net"))
                .is_some()
        );
        assert!(
            blocklist_name_match(&model, &BpfString::from_str_bytes(b"g.doubleclick.net"))
                .is_some()
        );
        assert!(
            blocklist_name_match(&model, &BpfString::from_str_bytes(b"ad-g.doubleclick.net"))
                .is_some()
        );

        assert!(
            blocklist_name_match(
                &model,
                &BpfString::from_str_bytes(b"securepubads.g.doubleclick.net")
            )
            .is_some()
        );
    }

    pub fn print_page(page: &NameBlocklistPage) {
        println!("Blocklist Page with {} entries:", page.entry_count);
        for i in 0..(page.entry_count as usize) {
            let offset = page.string_offset[i] & 0x7fff;
            let length = (page.string_offset[i + 1] & 0x7fff) - offset;
            let start_ptr = unsafe { (page as *const _ as *const u8).add(offset as _) };
            let bytes = unsafe { from_raw_parts(start_ptr, length as _) };
            println!("entry at offset {}: {}", offset, unsafe { str::from_utf8_unchecked(bytes) });
        }
    }

    pub fn _print_global_blocklist(model: &impl FilterModel) {
        let meta = model.metainfo().unwrap();
        println!(
            "page count: {}, generation: {}",
            meta.name_blocklist.page_count, meta.name_blocklist.generation
        );
        println!("pages:");
        for i in 0..meta.name_blocklist.page_count {
            print_page((model.name_blocklist()).get(i).unwrap());
        }
    }

    pub struct RawPage {
        pub strings_buffer: Vec<u8>,
        pub offset_buffer: Vec<u16>,
    }
    impl RawPage {
        pub fn new() -> Self {
            Self {
                strings_buffer: Vec::new(),
                offset_buffer: Vec::new(),
            }
        }

        // names must be pushed in correct order for ordered list!
        pub fn push_name(&mut self, name: &[u8], is_domain: bool) {
            assert!(name.len() > 0);
            let domain_tag = if is_domain { 0x8000u16 } else { 0 };
            self.offset_buffer.push(domain_tag | self.strings_buffer.len() as u16);
            for &b in name {
                self.strings_buffer.push(if b == b'.' { DOMAIN_SEP } else { b });
            }
        }

        pub fn emit_page(&mut self) -> NameBlocklistPage {
            self.offset_buffer.push(self.strings_buffer.len() as _);
            let mut page = NameBlocklistPage {
                entry_count: (self.offset_buffer.len() - 1) as _,
                string_offset: [0u16; _],
            };
            let strings_offset = self.offset_buffer.len() * size_of::<u16>() + size_of::<u16>();
            for (index, offset) in self.offset_buffer.iter().enumerate() {
                page.string_offset[index] = *offset + strings_offset as u16;
            }
            unsafe {
                ptr::copy(
                    self.strings_buffer.as_ptr(),
                    (&mut page as *mut _ as *mut u8).add(strings_offset),
                    self.strings_buffer.len(),
                );
            }
            self.offset_buffer.clear();
            self.strings_buffer.clear();
            page
        }
    }
}
