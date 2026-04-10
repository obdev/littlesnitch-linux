// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use crate::{
    co_re::*,
    context::{StaticBuffers, StringAndZero},
    strings_cache::identifier_for_string,
    unique_id::{Purpose, UniqueId},
};
use aya_ebpf::{
    bindings::BPF_NOEXIST, cty::c_void, helpers::generated::bpf_probe_read_kernel, macros::map,
    maps::HashMap,
};
use common::{
    StringId,
    node_cache::{MAX_PATH_COMPONENTS, NodeCacheTrait, NodeId, PathNode, PathRep},
};
use core::ptr;

#[map]
static NODE_ID_FOR_NODE: HashMap<PathNode, NodeId> = HashMap::with_max_entries(65536, 0);
#[map]
static NODE_FOR_NODE_ID: HashMap<NodeId, PathNode> = HashMap::with_max_entries(65536, 0);

// Keyed by mount ID (mnt_id from struct mount), which uniquely identifies each mounted filesystem
// instance. We previously used inode number + device ID, but btrfs uses ephemeral device IDs
// for subvolumes and there is no unique identifier available from userspace *and* kernel.
#[map]
static ROOT_NODES: HashMap<u32, NodeId> = HashMap::with_max_entries(8192, 0);

pub struct NodeCache {
    buffers: *mut StaticBuffers,
    unique_id: Option<UniqueId>,
}

impl NodeCache {
    pub fn new(buffers: *mut StaticBuffers) -> Self {
        Self { buffers, unique_id: None }
    }
}

impl NodeCacheTrait<Path, StringAndZero> for NodeCache {
    fn root_node_id(&self, root_path: &Path) -> Option<NodeId> {
        unsafe {
            let mut mnt_id: u32 = 0;
            let mnt_id_ptr = vfsmount_mnt_id_ptr(root_path.mnt as _);
            bpf_probe_read_kernel(
                &mut mnt_id as *mut u32 as *mut c_void,
                core::mem::size_of::<u32>() as u32,
                mnt_id_ptr as *const c_void,
            );
            ROOT_NODES.get(&mnt_id).cloned()
        }
    }

    fn id_for_node(&self, node: &PathNode) -> Option<NodeId> {
        unsafe { NODE_ID_FOR_NODE.get(node).cloned() }
    }

    fn node_for_id(&self, node_id: NodeId) -> Option<PathNode> {
        unsafe { NODE_FOR_NODE_ID.get(&node_id).cloned() }
    }

    fn string_id_buffer(&mut self) -> *mut [StringId; MAX_PATH_COMPONENTS] {
        unsafe { &mut (*self.buffers).string_ids }
    }

    fn name_id_context(&mut self) -> *mut StringAndZero {
        unsafe { &mut (*self.buffers).string }
    }

    fn insert_node(&mut self, node: &PathNode, node_id: NodeId) -> bool {
        // BPF_NOEXIST means that we don't want to overwrite existing entries
        if !NODE_ID_FOR_NODE.insert(node, node_id, BPF_NOEXIST as _).is_ok() {
            return false;
        }
        _ = NODE_FOR_NODE_ID.insert(node_id, node, 0);
        true
    }

    fn new_id(&mut self) -> NodeId {
        let unique_id = UniqueId::new(Purpose::NodeId);
        let node_id = NodeId(unique_id.get());
        self.unique_id = Some(unique_id);
        node_id
    }

    fn consume_id(&mut self) {
        if let Some(mut unique_id) = self.unique_id.take() {
            unique_id.consume();
        }
    }
}

// We currently obtain the path from a `struct path`, which represents a path within the mounted
// file system. In order to get absolute paths, we maintain a list of mount points (`ROOT_NODES`)
// and prepend the file system's mount point to the path's root.
// In theory, we could reconstruct the absolte path by continuing at the mount point's dentry
// within the parent mount. This requires access to `struct mount` where we only have
// `struct vfsmount` from `struct path`. `struct vfsmount` is embedded in `struct mount`, and
// the kernel uses `container_of()` to get from `struct vfsmount` to `struct mount` (see
// Linux implementation of `prepend_path()` in `d_path.c`). We need to take that step anyway
// to find `mnt_id` and it requires a bit of CO-RE acrobatics (see implementation of
// `vfsmount_mnt_id_ptr()`). Obtaining an integer value via `bpf_probe_read_kernel()` is easy,
// but not getting a CO-RE pointer to the parent `struct dentry`. So we rather stick with the
// `ROOT_NODES` approach where the parent information comes from user space.

pub struct Path {
    // References are static for the time our program runs.
    pub dentry: &'static dentry,
    pub mnt: &'static vfsmount,
}

impl Path {
    pub fn new(path: &path) -> Self {
        unsafe {
            Self {
                dentry: &*path_dentry(path as _),
                mnt: &*path_mnt(path as _),
            }
        }
    }
}

// This implementation of PathRep defines by what path an executable is identified. We choose
// to work with `struct dentry` for executable identification, not with path strings which
// would be available in `sched_process_exec()`, because dentry has all symlinks resolved.
// We stop parent iteration when the dentry matches the mount's root dentry or when it is NULL.
// This way we exactly reproduce the paths seen from user space.

impl PathRep<StringAndZero> for Path {
    fn name_id(&self, buffer: *mut StringAndZero) -> StringId {
        let buffer = unsafe { &mut *buffer };
        buffer.string.clear(buffer.zero);
        buffer.string.update(|bytes| unsafe {
            let len = (&*dentry_name(self.dentry as _))
                .__bindgen_anon_1
                .__bindgen_anon_1
                .len
                .min(bytes.len() as _);
            let r = bpf_probe_read_kernel(
                bytes as *mut u8 as *mut c_void,
                len,
                (&*dentry_name(self.dentry as _)).name as *const c_void,
            );
            if r < 0 { 0 } else { len as _ }
        });
        identifier_for_string(&buffer.string)
    }

    fn parent(&self) -> Option<Self> {
        let root_node = unsafe { vfsmount_root(self.mnt) };
        if !ptr::eq(self.dentry, root_node)
            && let Some(parent) = unsafe { dentry_parent(self.dentry as *const _).as_ref() }
        {
            Some(Path { dentry: parent, mnt: self.mnt })
        } else {
            None
        }
    }
}
