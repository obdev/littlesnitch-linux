// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::demo_node_cache::{DemoExecutable, DemoNodeCache};
use aya::{Ebpf, maps::MapData};
use common::{
    NodeFeatures,
    bitset::BitSet,
    node_cache::{NodeCacheTrait, NodeId},
};
use std::path::PathBuf;

pub struct DemoNodeManager {
    pub node_features: aya::maps::HashMap<MapData, NodeId, NodeFeatures>,

    // Note that tthe PID here is a thread PID and many entries may not be shown in a normal
    // `ps` output. This becomes important if we ever need to celan up lost entries.
    pub pid_to_node_id: aya::maps::HashMap<MapData, i32, NodeId>,

    pub node_cache: DemoNodeCache,
}

impl DemoNodeManager {
    pub fn new(ebpf: &mut Ebpf) -> Self {
        let raw_map = ebpf.take_map("NODE_FEATURES").unwrap();
        let node_features =
            aya::maps::HashMap::<_, NodeId, NodeFeatures>::try_from(raw_map).unwrap();

        let raw_map = ebpf.take_map("PID_TO_NODE_ID").unwrap();
        let pid_to_node_id = aya::maps::HashMap::<_, i32, NodeId>::try_from(raw_map).unwrap();

        let node_cache = DemoNodeCache::new(ebpf);
        Self { node_features, pid_to_node_id, node_cache }
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
