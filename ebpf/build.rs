// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

use std::{env, path::PathBuf};

use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_arch == "bpf" {
        // declare dependency on BPF linker as outlined in comment above
        let bpf_linker = which("bpf-linker").unwrap();
        println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());

        // declare dependency on C module:
        println!("cargo::rerun-if-changed=co-re/co-re.c");
        println!("cargo::rerun-if-changed=co-re/co-re.h");

        // compile C module to LLVM bitcode
        let bitcode_file = cc::Build::new()
            .compiler("clang")
            .no_default_flags(true)
            .file("co-re/co-re.c")
            .flag("-g")
            .flag("-emit-llvm")
            .flag("--target=bpf")
            .compile_intermediates()
            .into_iter()
            .next()
            .expect("bitcode file should compile successfully");

        // link with bitcode file:
        println!("cargo::rustc-link-arg={}", bitcode_file.display());
    }

    // generate bindings for Rust
    let bindings = bindgen::Builder::default()
        .use_core()
        .opaque_type("cred|super_block|inode|dentry|vfsmount|path|file|mm_struct|task_struct|linux_binprm")
        .header("co-re/co-re.h")
        .generate()
        .expect("generating bindings should succeed");

    // write rust bindings of C module to OUT_DIR
    let out_dir = env::var("OUT_DIR").expect("`OUT_DIR` should be set in a buildscript");
    let out_file_path = PathBuf::from(out_dir).join("co-re.rs");
    bindings
        .write_to_file(out_file_path)
        .expect("writing bindings should succeed");
}

