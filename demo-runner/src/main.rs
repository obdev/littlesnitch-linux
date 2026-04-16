// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

mod demo_blocklist;
mod demo_blocklist_load_from_file;
mod demo_ebpf_proxy;
mod demo_ebpf_proxy_dump_dns;
mod demo_ebpf_proxy_event_handling;
mod demo_ebpf_proxy_garbage_collect;
mod demo_filter_maps;
mod nano_time;
mod demo_node_cache;
mod demo_node_manager;
mod demo_strings_cache;

use clap::Parser;
use common::{NodeFeatures, flow_types::Verdict, network_filter::filter_model::FilterMetainfo};
use demo_ebpf_proxy::DemoEbpfProxy;
use libc::{FD_SET, FD_ZERO, fd_set, select, signal, timeval};
use log::debug;
use std::{
    ffi::c_void,
    fs::File,
    io::{BufRead, BufReader},
    mem::MaybeUninit,
    os::fd::AsRawFd,
    path::Path,
    ptr,
    time::{Duration, Instant, SystemTime},
};

const GABAGE_COLLECT_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: std::path::PathBuf,
}

static mut REQUEST_DUMP: bool = false;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let Opt { cgroup_path } = opt;

    let mut ebpf = DemoEbpfProxy::new();
    ebpf.start_logger_thread();
    ebpf.node_manager.add_node_features(
        NodeFeatures::APP_MANAGER,
        &["/usr/lib/systemd/systemd", "/usr/bin/gnome-shell"],
    );
    if let Ok(file) = File::open("/etc/shells") {
        for line_result in BufReader::new(file).lines() {
            if let Ok(line) = line_result {
                if line.starts_with("#") || line.is_empty() {
                    continue;
                }
                println!("adding shell: {}", line);
                ebpf.node_manager.add_node_features(NodeFeatures::NON_PARENT, &[line.as_str()]);
            } else {
                break;
            }
        }
    }

    let start = Instant::now();
    let page_count = ebpf.filter_engine.load_blocklists(&[
        (&Path::new("blocked_hosts.txt"), false),
        (&Path::new("blocked_domains.txt"), true),
    ]);
    let mut metainfo = FilterMetainfo::new(Verdict::Allow);
    metainfo.name_blocklist.page_count = page_count as _;
    ebpf.filter_engine.write_metainfo(&metainfo);
    println!("reading, merging, sorting and uploading blocklists took {:.3?}", start.elapsed());

    ebpf.attach(cgroup_path)?;

    let fd = ebpf.events.as_raw_fd();
    let mut fd_set = MaybeUninit::<fd_set>::uninit();
    unsafe {
        FD_ZERO(fd_set.as_mut_ptr());
        FD_SET(fd, fd_set.as_mut_ptr());
    }
    unsafe {
        signal(3, signal_handler as *mut c_void as usize);
    }
    let mut next_garbage_collect = SystemTime::now();
    println!("entering event queue loop");
    loop {
        ebpf.poll_events();
        unsafe {
            if REQUEST_DUMP {
                ebpf.garbage_collect_flows();
                ebpf.dump_active_flows();
                ebpf.dump_dns_cache();
                ebpf.node_manager.node_cache.strings_cache.dump_cache();
                ebpf.node_manager.dump_pid_cache();
                REQUEST_DUMP = false;
            }
        }
        // ignore errors, might just be EINTR
        unsafe {
            let mut timeout = timeval { tv_sec: 0, tv_usec: 200_000 };
            select(fd + 1, fd_set.as_mut_ptr(), ptr::null_mut(), ptr::null_mut(), &mut timeout)
        };
        let now = SystemTime::now();
        if now > next_garbage_collect {
            next_garbage_collect = now + GABAGE_COLLECT_INTERVAL;
            ebpf.garbage_collect_flows();
        }
    }
}

extern "C" fn signal_handler(_signr: i32) {
    unsafe {
        REQUEST_DUMP = true;
    }
}
