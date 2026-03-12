// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

pub mod co_re {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/co-re.rs"));
}

mod context;
mod current_executable;
mod dn_expand;
mod dns_cache;
mod event_queue;
mod filter_engine_connection;
mod flow_cache;
mod helpers;
mod ip_parser;
mod kernel_filter_model;
mod node_cache;
mod socket_properties;
mod strings_cache;
mod unique_id;

use crate::{
    co_re::*,
    context::Context,
    current_executable::{
        report_exec_attempt_with_path, report_exec_success, report_sched_process_exec,
        report_sched_process_exit, report_sched_process_fork,
    },
    dns_cache::name_for_address,
    event_queue::enqueue_event,
    filter_engine_connection::FilterEngineConnection,
    kernel_filter_model::KernelFilterModel,
    socket_properties::get_socket_properties,
};
use aya_ebpf::{
    bindings::{
        bpf_sock_addr,
        sk_action::{SK_DROP, SK_PASS},
    },
    helpers::generated::bpf_get_socket_cookie,
    macros::{cgroup_skb, cgroup_sock, cgroup_sock_addr, fentry, fexit, tracepoint},
    programs::{
        FEntryContext, FExitContext, SkBuffContext, SockAddrContext, SockContext, TracePointContext,
    },
};
use aya_log_ebpf::error;
use common::{
    event::BLOCKED,
    flow_types::{IpAddress, Verdict, VerdictReason},
    network_filter::{
        filter_engine::FilterEngine, filter_model::FilterModel,
        port_table_search::SpecificPortTableSearch,
    },
};

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const _ETHER_TYPE_ARP: u16 = 0x0806;

#[cgroup_sock(sock_create)] // since Linux 4.10
pub fn cgroup_sock_create(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as _) };
    socket_properties::socket_opened(cookie);
    SK_PASS as _
}

#[cgroup_sock(sock_release)] // since Linux 4.10
pub fn cgroup_sock_release(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock as _) };
    socket_properties::socket_closed(cookie);
    SK_PASS as _
}

#[cgroup_sock_addr(connect4)] // since Linux 4.17
pub fn cgroup_sock_addr_connect4(ctx: SockAddrContext) -> i32 {
    handle_sock_addr(ctx.sock_addr, false, false)
}

#[cgroup_sock_addr(connect6)] // since Linux 4.17
pub fn cgroup_sock_addr_connect6(ctx: SockAddrContext) -> i32 {
    handle_sock_addr(ctx.sock_addr, true, false)
}

#[cgroup_sock_addr(sendmsg4)] // since Linux 4.17
pub fn cgroup_sock_addr_sendmsg4(ctx: SockAddrContext) -> i32 {
    handle_sock_addr(ctx.sock_addr, false, true)
}

#[cgroup_sock_addr(sendmsg6)] // since Linux 4.17
pub fn cgroup_sock_addr_sendmsg6(ctx: SockAddrContext) -> i32 {
    handle_sock_addr(ctx.sock_addr, true, true)
}

#[fentry(function = "bprm_execve")] // since Linux 5.5
pub fn fentry_bprm_execve(ctx: FEntryContext) -> i32 {
    // We have very special requirements for our interception point: The kernel must have the
    // executable file open so that we have access to a `struct dentry` because we need the
    // hierarchy of inodes, not just the path name. The inode hierarchy is always a realpath
    // while the path name may contain symlinks, "../" , "./" and so on. So we must intercept
    // *after* the kernel opens the file but *before* it finds a responsible interpreter because
    // once it has the interpreter, the file is closed and the interpreter executable is opened.
    // The call path is do_execveat_common() -> bprm_execve() -> exec_binprm(). All of these
    // functions are static (private to the module).
    // do_execveat_common() receives a file name string as parameter, so we can't intercept before
    // it. exec_binprm() is called only once, so it may be inlined by the compiler and thus not
    // available for tracing (actually seen on Intel architecture).
    // So our choices are `bprm_execve()` (static) and `security_bprm_creds_for_exec()` (public,
    // but may be a `static inline` dummy if the kernel is compiled without `CONFIG_SECURITY`).
    // In any case we need to intercept the function entry point to get access to the `bprm`
    // function parameter. However, the function may fail, so we should also intercept an outer
    // exit to register the new executable for the PID only on success. The most likely point of
    // failure after permission checks is `exec_binprm()` where the interpreter may fail to load.
    // Our best interception point is therefore `bprm_execve()`. When it returns successfully,
    // exec was done. Although it's static, there are two calls to it and inlining by the compiler
    // is unlikely.
    unsafe {
        let bprm: *const linux_binprm = ctx.arg(0);
        report_exec_attempt_with_path(&*linux_binprm_path(bprm));
    }
    0 // return value is ignored
}

#[fexit(function = "bprm_execve")] // since Linux 5.5
pub fn fexit_bprm_execve(ctx: FExitContext) -> i32 {
    let return_value: i32 = ctx.arg(1);
    report_exec_success(return_value);
    0 // return value is ignored
}

#[tracepoint] // since Linux 4.7
pub fn tracepoint_sched_process_exec(ctx: TracePointContext) -> i32 {
    _ = handle_sched_process_exec(ctx);
    0
    // [...]
    // field:__data_loc char[] filename;	offset:8;	size:4;	signed:0;
    // field:pid_t pid;	offset:12;	size:4;	signed:1;
    // field:pid_t old_pid;	offset:16;	size:4;	signed:1;
}

#[tracepoint] // since Linux 4.7
pub fn tracepoint_sched_process_fork(ctx: TracePointContext) -> i32 {
    _ = handle_sched_process_fork(ctx);
    0
    // [...]
    // field:__data_loc char[] parent_comm;	offset:8;	size:4;	signed:0;
    // field:pid_t parent_pid;	offset:12;	size:4;	signed:1;
    // field:__data_loc char[] child_comm;	offset:16;	size:4;	signed:0;
    // field:pid_t child_pid;	offset:20;	size:4;	signed:1;
}

#[tracepoint] // since Linux 4.7
pub fn tracepoint_sched_process_exit(ctx: TracePointContext) -> i32 {
    _ = handle_sched_process_exit(ctx);
    0
    // [...]
    // field:char comm[16];	offset:8;	size:16;	signed:0;
    // field:pid_t pid;	offset:24;	size:4;	signed:1;
    // field:int prio;	offset:28;	size:4;	signed:1;
    // field:bool group_dead;	offset:32;	size:1;	signed:0;
}

/* not needed yet
#[tracepoint]
pub fn tracepoint_sys_exit_mount(_ctx: TracePointContext) -> i32 {
    // Note: called in fast succession when setting up a virtual environment.
    unsafe {
        bpf_printk!(b"did mount");
    }
    0
    // [...]
    // field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    // field:long ret;	offset:16;	size:8;	signed:1;
}

#[tracepoint]
pub fn tracepoint_sys_exit_fsmount(_ctx: TracePointContext) -> i32 {
    unsafe {
        bpf_printk!(b"did fsmount");
    }
    0
    // [...]
    // field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    // field:long ret;	offset:16;	size:8;	signed:1;
}

*/

#[cgroup_skb] // linux 4.10
pub fn cgroup_skb_transmit(ctx: SkBuffContext) -> i32 {
    handle_packet(ctx, false)
}

#[cgroup_skb] // linux 4.10
pub fn cgroup_skb_receive(ctx: SkBuffContext) -> i32 {
    handle_packet(ctx, true)
}

fn handle_sock_addr(addr: *mut bpf_sock_addr, is_ipv6: bool, _is_sendmsg: bool) -> i32 {
    // Only called for outgoing packets.
    // If this is a sendmsg() call, we could, in principle, get the local address and port.
    let cookie = unsafe { bpf_get_socket_cookie(addr as _) };
    if let Some(properties) = get_socket_properties(cookie, true) {
        let addr = unsafe { &*addr };
        addr.protocol;
        let mut verdict = Verdict::Allow;
        enqueue_event(|event| {
            event.connection_identifier.process_pair = properties.owner.clone();
            event.connection_identifier.remote_address = if is_ipv6 {
                IpAddress::v6(addr.user_ip6)
            } else {
                IpAddress::v4(addr.user_ip4)
            };
            event.connection_identifier.remote_name =
                name_for_address(&event.connection_identifier.remote_address, &properties.owner);
            event.connection_identifier.is_inbound = false; // called for outbound only!
            event.connection_identifier.protocol = addr.protocol as _;
            event.connection_identifier.port = u16::from_be(addr.user_port as u16);

            let reason;
            (verdict, reason) = if let Some(model) = KernelFilterModel::shared()
                && let Some(metainfo) = model.metainfo()
            {
                let mut search_spec = SpecificPortTableSearch::new(metainfo.default_verdict);
                model.evaluate_network_filter(
                    FilterEngineConnection::wrap(&event.connection_identifier),
                    &mut search_spec,
                );
                search_spec.result()
            } else {
                (Verdict::Allow, VerdictReason::Other)
            };
            if verdict != Verdict::Deny {
                return false; // discard this event, we will receive it again at other function
            }
            event.payload.ephemeral_port = 0; // local port usually not yet assigned
            event.payload.changes = BLOCKED;
            event.payload.verdict_reason = reason;
            event.payload.bytes_received = 0;
            event.payload.bytes_sent = 0;
            true // send event
        });
        match verdict {
            Verdict::Deny => SK_DROP as _,
            _ => SK_PASS as _,
        }
    } else {
        SK_PASS as _
    }
}

fn handle_sched_process_exec(ctx: TracePointContext) -> Result<(), i64> {
    // [...]
    // field:__data_loc char[] filename;	offset:8;	size:4;	signed:0;
    // field:pid_t pid;	offset:12;	size:4;	signed:1;
    // field:pid_t old_pid;	offset:16;	size:4;	signed:1;
    unsafe {
        let new_pid: i32 = ctx.read_at(12)?;
        let old_pid: i32 = ctx.read_at(16)?;
        report_sched_process_exec(old_pid, new_pid);
    }
    Ok(())
}

fn handle_sched_process_fork(ctx: TracePointContext) -> Result<(), i64> {
    // [...]
    // field:__data_loc char[] parent_comm;	offset:8;	size:4;	signed:0;
    // field:pid_t parent_pid;	offset:12;	size:4;	signed:1;
    // field:__data_loc char[] child_comm;	offset:16;	size:4;	signed:0;
    // field:pid_t child_pid;	offset:20;	size:4;	signed:1;
    unsafe {
        let parent_pid: i32 = ctx.read_at(12)?;
        let child_pid: i32 = ctx.read_at(20)?;
        report_sched_process_fork(parent_pid, child_pid);
    }
    Ok(())
}

fn handle_sched_process_exit(ctx: TracePointContext) -> Result<(), i64> {
    // [...]
    // field:char comm[16];	offset:8;	size:16;	signed:0;
    // field:pid_t pid;	offset:24;	size:4;	signed:1;
    // field:int prio;	offset:28;	size:4;	signed:1;
    // field:bool group_dead;	offset:32;	size:1;	signed:0;
    unsafe {
        let pid = ctx.read_at(24)?;
        report_sched_process_exit(pid);
    }
    Ok(())
}

fn handle_packet(ctx: SkBuffContext, is_inbound: bool) -> i32 {
    let ether_type = u16::from_be(ctx.skb.protocol() as _);
    if ether_type != ETHER_TYPE_IPV4 && ether_type != ETHER_TYPE_IPV6 {
        error!(ctx, "discarding packet type {:x}", ether_type);
        return SK_PASS as _; // ignore other packet types
    }
    let ctx = Context::get(ctx.skb, is_inbound);
    // We must be careful here: If we enumerate all result cases, the compiler finds out
    // that Verdict::Allow is the same as SK_PASS and Verdict::Deny the same as SK_DROP
    // and it just returns the raw value of the verdict.
    // The verifier, on the other hand, sees the full possible value range of Verdict
    // (which is 0..256 for u8) and rejects our program.
    match ctx.update_from_packet() {
        Some(Verdict::Deny) => SK_DROP as _,
        _ => SK_PASS as _,
    }
}

// This is actually not inline assembler code, but only needed when inline assembler is
// needed as well. For rust-analyzer, this code stays disabled.
#[cfg(feature = "with-inline-assembler")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(target_arch = "bpf"))]
pub fn main() {} // never used, make analyzer happy
