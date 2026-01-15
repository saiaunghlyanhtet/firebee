//! Build script for the `firebee`.

extern crate libbpf_cargo;

use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC_INGRESS: &str = "src/bpf/firebee.bpf.c";
const SRC_EGRESS: &str = "src/bpf/firebee_egress.bpf.c";

fn main() {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    );

    let bpf_dir = manifest_dir.join("src").join("bpf");

    let out_ingress = bpf_dir.join("firebee.skel.rs");
    let out_egress = bpf_dir.join("firebee_egress.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    let vmlinux_path = vmlinux::include_path_root().join(&arch);
    let clang_args = vec![OsStr::new("-I"), vmlinux_path.as_os_str()];

    // Build XDP ingress program
    SkeletonBuilder::new()
        .source(SRC_INGRESS)
        .clang_args(&clang_args)
        .build_and_generate(&out_ingress)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC_INGRESS}");

    // Build TC egress program
    SkeletonBuilder::new()
        .source(SRC_EGRESS)
        .clang_args(&clang_args)
        .build_and_generate(&out_egress)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC_EGRESS}");

    // Rerun if common headers change
    println!("cargo:rerun-if-changed=src/bpf/firebee_common.h");
    println!("cargo:rerun-if-changed=src/bpf/firebee_helpers.h");
}
