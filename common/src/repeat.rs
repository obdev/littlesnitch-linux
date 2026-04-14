// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

#[cfg(target_arch = "bpf")]
use aya_ebpf::{cty::c_void, helpers::generated::bpf_loop};

#[derive(PartialEq, Eq)]
#[repr(i64)]
pub enum LoopReturn {
    LoopContinue = 0,
    LoopBreak = 1,
}

pub type LoopFunction<C> = extern "C" fn(u64, &mut C) -> LoopReturn;

#[cfg(target_arch = "bpf")]
#[inline(always)]
pub fn repeat<C>(count: u64, function: LoopFunction<C>, context: &mut C) -> u64 {
    unsafe {
        bpf_loop(
            count as _,
            function as *mut c_void,
            context as *mut _ as *mut c_void,
            0,
        ) as _
    }
}

#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub fn repeat<C>(count: u64, function: LoopFunction<C>, context: &mut C) -> u64 {
    for i in 0..(count as u64) {
        if function(i, context) == LoopReturn::LoopBreak {
            return i + 1;
        }
    }
    count
}

/// `repeat_closure()` is a more convenient wrapper around `repeat()`: it accepts a closure
/// instead of a "C" function and allows capturing variables instead of a context struct.
/// However, it results in different verifier complexity. May be better or worse than
/// "C" function approach.
pub fn repeat_closure(count: usize, closure: impl FnMut(usize) -> LoopReturn) -> usize {
    let mut ctx = RepeatClosureCtx { closure };
    repeat(count as u64, repeat_closure_inner, &mut ctx) as usize
}

struct RepeatClosureCtx<F: FnMut(usize) -> LoopReturn> {
    closure: F,
}

extern "C" fn repeat_closure_inner<F: FnMut(usize) -> LoopReturn>(
    index: u64,
    ctx: &mut RepeatClosureCtx<F>,
) -> LoopReturn {
    (ctx.closure)(index as usize)
}
