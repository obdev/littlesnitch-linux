// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::demo_node_cache::{DemoNodeCache, DemoExecutable};
use aya::{maps::MapData, Ebpf};
use common::{
    NodeFeatures,
    bitset::BitSet,
    node_cache::{NodeCacheTrait, NodeId},
};
use log::{debug, error, warn};
use std::{
    collections::HashSet,
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    path::PathBuf,
};

pub struct DemoNodeManager {
    // The mount points in user space are root nodes for the kernel.
    pub root_nodes: aya::maps::HashMap<MapData, u32, NodeId>,
    pub node_features: aya::maps::HashMap<MapData, NodeId, NodeFeatures>,

    // Note that tthe PID here is a thread PID and many entries may not be shown in a normal
    // `ps` output. This becomes important if we ever need to celan up lost entries.
    pub pid_to_node_id: aya::maps::HashMap<MapData, i32, NodeId>,

    pub node_cache: DemoNodeCache,
}

impl DemoNodeManager {
    pub fn new(ebpf: &mut Ebpf) -> Self {
        let raw_map = ebpf.take_map("ROOT_NODES").unwrap();
        let root_nodes = aya::maps::HashMap::<_, u32, NodeId>::try_from(raw_map).unwrap();

        let raw_map = ebpf.take_map("NODE_FEATURES").unwrap();
        let node_features =
            aya::maps::HashMap::<_, NodeId, NodeFeatures>::try_from(raw_map).unwrap();

        let raw_map = ebpf.take_map("PID_TO_NODE_ID").unwrap();
        let pid_to_node_id = aya::maps::HashMap::<_, i32, NodeId>::try_from(raw_map).unwrap();

        let node_cache = DemoNodeCache::new(ebpf);
        Self {
            root_nodes,
            node_features,
            pid_to_node_id,
            node_cache,
        }
    }

    pub fn update_mounts(&mut self) {
        match mount_infos() {
            Ok(mount_infos) => {
                let mut old_mount_ids: HashSet<_> =
                    self.root_nodes.keys().filter_map(|r| r.ok()).collect();
                for MountInfo { path, mount_id } in mount_infos {
                    let node_id = match self
                        .node_cache
                        .node_id_for_path(DemoExecutable(path.clone()))
                    {
                        Some(id) => id,
                        None => {
                            warn!("Could not obtain node ID for {:?}", path);
                            continue;
                        }
                    };
                    debug!("found mountpoint: {:?} mount_id {}", path, mount_id);
                    _ = self.root_nodes.insert(mount_id, node_id, 0);
                    old_mount_ids.remove(&mount_id);
                }
                // old_mount_ids contains all mounts which are no longer valid. Remove them.
                for mount_id in old_mount_ids.iter() {
                    _ = self.root_nodes.remove(mount_id);
                }
            }
            Err(error) => {
                error!("*** Error obtaining mount paths: {}", error);
            }
        }
    }

    pub fn add_node_features(&mut self, features: BitSet, paths: &[&str]) {
        for path_str in paths {
            match self.node_cache.node_id_for_path(DemoExecutable(PathBuf::from(path_str))) {
                Some(node_id) => {
                    let mut feat = self.node_features.get(&node_id, 0).unwrap_or_default();
                    feat.0 += features;
                    _ = self.node_features.insert(&node_id, &feat, 0);
                }
                None => println!("*** Error adding feature for node: {}", path_str),
            }
        }
    }

    pub fn dump_pid_cache(&self) {
        println!("--- PID Cache ---");
        for keyvalue in self.pid_to_node_id.iter() {
            let (pid, node_id) = match keyvalue {
                Ok((pid, node_id)) => (pid, node_id),
                Err(err) => {
                    println!("aborting iteration with error: {:?}", err);
                    break;
                }
            };
            let path = self.node_cache.path_for_node_id(node_id);
            println!("pid {:6}: {}", pid, path);
        }
    }
}

struct MountInfo {
    path: PathBuf,
    mount_id: u32,
}

/// Parse /proc/self/mountinfo to get mount points with their mount IDs.
/// Each line has the format:
///   mountID parentID major:minor root mountpoint options ... - fstype source superoptions
/// Space and '\' (and possibly other characters) are encoded in octal as e.g. \040 for space.
/// We use the mountID (first field) as the key for ROOT_NODES because it matches mnt_id in
/// the kernel's struct mount.
fn mount_infos() -> anyhow::Result<Vec<MountInfo>> {
    let data = std::fs::read("/proc/self/mountinfo")?;
    let mut result = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Some(info) = parse_mountinfo_line(line) else {
            warn!("could not parse mountinfo line: {:?}", String::from_utf8_lossy(line));
            continue;
        };
        result.push(info);
    }
    Ok(result)
}

fn parse_mountinfo_line(line: &[u8]) -> Option<MountInfo> {
    let mut fields = line.splitn(6, |&b| b == b' ');
    let mount_id_bytes = fields.next()?; // mountID
    fields.next()?; // parentID
    fields.next()?; // major:minor
    fields.next()?; // root
    let mountpoint_bytes = fields.next()?; // mountpoint

    let mount_id = str::from_utf8(mount_id_bytes).ok()?.parse::<u32>().ok()?;
    let path = PathBuf::from(OsString::from_vec(unescape_mountinfo_path(mountpoint_bytes)));

    Some(MountInfo { path, mount_id })
}

/// Unescape octal sequences (\NNN) in mountinfo paths.
fn unescape_mountinfo_path(path: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'\\' && i + 3 < path.len() {
            let a = path[i + 1].wrapping_sub(b'0');
            let b = path[i + 2].wrapping_sub(b'0');
            let c = path[i + 3].wrapping_sub(b'0');
            if a < 8 && b < 8 && c < 8 {
                result.push((a << 6) | (b << 3) | c);
                i += 4;
                continue;
            }
        }
        result.push(path[i]);
        i += 1;
    }
    result
}
