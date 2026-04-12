// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::dns_cache::PacketProvider;
use common::{
    DOMAIN_SEP,
    bpf_string::BpfString,
    repeat::{LoopReturn, repeat},
};

pub fn dn_expand<P: PacketProvider>(
    packet_provider: &P,
    index: &mut usize,
    dns_msg_start_index: u16,
    result: &mut BpfString,
) {
    result.update(|buffer| {
        dn_expand_to_buffer(
            packet_provider,
            index,
            dns_msg_start_index,
            buffer as *mut u8,
            buffer.len(),
        ) as u8
    });
}

/// Decode an RFC‑1035 DNS name that may use compression pointers.
///
/// The compressed name is read from the packet provided by `packet_provider` starting
/// at offset `index`. On return, `index` was set to the first position after the name.
/// The resulting string is written to `result`, which is assumed to be zero-filled.
///
/// The function will simply truncate the output if it does not fit into `output_buffer`.
/// If the input message is malformed (e.g. out‑of‑bounds pointers, loops, excessively
/// deep recursion), the function stops decoding and returns the bytes read up to that
/// point. No error code is returned.
#[inline(never)]
fn dn_expand_to_buffer<P: PacketProvider>(
    packet_provider: &P,
    index: &mut usize,
    dns_msg_start_index: u16,
    result_buffer: *mut u8,
    result_len: usize,
) -> usize {
    let mut ctx = LoopContext {
        packet_provider,
        src_index: *index,
        index_ref: index,
        dest: result_buffer,
        dest_index: 0,
        dest_len: result_len,
        src_len: packet_provider.len(),
        dns_msg_start_index,
        did_jump: false,
    };
    repeat(126, dn_expand_inner, &mut ctx);
    if !ctx.did_jump {
        *ctx.index_ref = ctx.src_index;
    }
    // `result` is initialized to 0, so no need to 0-terminate
    // But remove trailing domain separator
    unsafe {
        let last_ptr = ctx.dest.add(ctx.dest_index as usize - 1);
        if ctx.dest_index > 0 && *last_ptr == DOMAIN_SEP {
            *last_ptr = 0;
            ctx.dest_index -= 1;
        }
    }
    ctx.dest_index
}

struct LoopContext<'a, P: PacketProvider> {
    pub packet_provider: &'a P,
    pub index_ref: &'a mut usize,
    pub dest: *mut u8,            // destination buffer for resulting string
    pub src_index: usize,         // index in data packet
    pub dest_index: usize,        // index in destination buffer
    pub src_len: usize,           // packet data length
    pub dest_len: usize,          // destination buffer length
    pub dns_msg_start_index: u16, // start of DNS packet within data packet
    pub did_jump: bool,           // internally used
}

extern "C" fn dn_expand_inner<P: PacketProvider>(
    _index: u64,
    ctx: &mut LoopContext<P>,
) -> LoopReturn {
    let len_byte = match get_byte(ctx.packet_provider, ctx.src_index) {
        Some(b) => b,
        None => return LoopReturn::LoopBreak,
    };
    ctx.src_index += 1;
    if len_byte & 0xC0 == 0xC0 {
        // We have a pointer (two high bits set). We need two bytes for a pointer.
        let b2 = match get_byte(ctx.packet_provider, ctx.src_index) {
            Some(b) => b,
            None => return LoopReturn::LoopBreak,
        };

        // Compute the pointer offset: 14 bits from the two bytes
        let jump_target = ctx.dns_msg_start_index as usize
            + ((((len_byte & 0x3F) as usize) << 8) | (b2 as usize));
        // Safety checks: the target is inside the message, prevent infinite loop
        if jump_target >= ctx.src_len {
            ctx.src_index -= 1; // stop before the length byte
            return LoopReturn::LoopBreak;
        }

        // Only count the 2 bytes of the pointer once
        if !ctx.did_jump {
            ctx.did_jump = true;
            *ctx.index_ref = ctx.src_index as usize + 1; // we are jumping -- this is the last time `index` is set
        }

        // Follow the pointer
        ctx.src_index = jump_target;
    } else {
        // Normal label: 1 <= length <= 63
        let label_len = (len_byte & 0x3f) as usize; // let verifier know our value range
        if label_len == 0 {
            return LoopReturn::LoopBreak; // end of name
        }

        // Ensure we have enough bytes for this label.
        if ctx.src_index + label_len > ctx.src_len {
            ctx.src_index = ctx.src_len; // consume the rest of the input buffer, but don't copy to output
            return LoopReturn::LoopBreak;
        }
        // If the label plus dot does not fit, abort
        if ctx.dest_index + label_len + 1 > ctx.dest_len {
            return LoopReturn::LoopBreak;
        }
        // copy label into result buffer
        ctx.packet_provider.load_bytes(
            ctx.src_index,
            unsafe { ctx.dest.add(ctx.dest_index) },
            label_len,
        );
        ctx.dest_index += label_len;
        ctx.src_index += label_len;
        // Add a domain separator between labels. Trailing domain separator will be removed.
        if ctx.dest_index < ctx.dest_len {
            unsafe {
                *ctx.dest.add(ctx.dest_index) = DOMAIN_SEP;
            }
            ctx.dest_index += 1;
        }
    }
    LoopReturn::LoopContinue
}

// Helper to read a byte safely, returning None if out of bounds.
fn get_byte(packet_provider: &impl PacketProvider, idx: usize) -> Option<u8> {
    let mut value = 0u8;
    packet_provider.load_bytes(idx, &mut value, 1)?;
    Some(value)
}
