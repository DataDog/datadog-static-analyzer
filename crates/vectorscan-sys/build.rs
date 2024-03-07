// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// Git repository information about a dependency to compile with CMake.
/// These are fetched during build time to avoid using git submodules.
struct Dependency {
    /// The repository URL
    url: String,
    /// The commit hash to pin to
    commit_hash: String,
    /// The folder that will contain the fetched source of this dependency
    source_path: PathBuf,
}

impl Dependency {
    fn new(pretty_name: &str, url: &str, commit_hash: &str) -> Self {
        let source_path = PathBuf::from(env::var("OUT_DIR").unwrap())
            .join("vendored-sources")
            .join(pretty_name);
        Self {
            url: url.to_string(),
            commit_hash: commit_hash.to_string(),
            source_path,
        }
    }
}

/// At a high level, this build script builds [Vectorscan](https://github.com/VectorCamp/vectorscan), a fork
/// of [Hyperscan](https://github.com/intel/hyperscan), a high-performance multiple regex matching library.
///
/// The freshly-built `hs` library is then announced to rustc's linker for use in the compilation process.
///
/// This script can also build [Chimera](https://intel.github.io/hyperscan/dev-reference/chimera.html), which
/// is an officially-supported regex engine that functions as a hybrid between Hyperscan and PCRE,
/// with full support for PCRE syntax. While disabled by default, Chimera can be activated with feature `chimera`.
///
/// Lastly, `bindgen` is used to automatically create low-level bindings between Hyperscan's C ABI and Rust.
/// These bindings are pre-generated at `src/bindings_hs.rs` and `src/bindings_ch.rs` for convenience (so
/// that library consumers don't need to install multiple dependencies just to generate the required bindings).
///
/// However, if compiled with the `generate-bindings` feature, this crate will freshly generate bindings
/// and save them to its `OUT_DIR`.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let hs_dependency = Dependency::new(
        "vectorscan-5.4.11",
        "https://github.com/VectorCamp/vectorscan",
        "d29730e1cb9daaa66bda63426cdce83505d2c809",
    );
    let pcre_dependency = Dependency::new(
        "pcre-8.45",
        "https://github.com/luvit/pcre",
        "5c78f7d5d7f41bdd4be4867ef3a1030af3e973e3",
    );

    let dependencies = if cfg!(feature = "chimera") {
        vec![&hs_dependency, &pcre_dependency]
    } else {
        vec![&hs_dependency]
    };

    for dependency in dependencies {
        if !dependency.source_path.exists() {
            assert!(fetch_dependency(dependency));
        }
    }

    match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "windows" => todo!("Vectorscan cannot yet be compiled for os `windows`"),
        "macos" => println!("cargo:rustc-link-lib=c++"),
        "linux" => println!("cargo:rustc-link-lib=stdc++"),
        _ => println!("cargo:rustc-link-lib=stdc++"),
    }

    let mut hs_cmake = cmake::Config::new(hs_dependency.source_path);
    hs_cmake
        // Override Vectorscan's default build configuration.
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_BENCHMARKS", "OFF");

    #[cfg(feature = "chimera")]
    {
        // Turn on the Chimera build flag, and point it to the extracted pcre folder.
        hs_cmake
            .define("PCRE_SOURCE", &pcre_dependency.source_path)
            .define("BUILD_CHIMERA", "ON")
            .cflag("-Wno-unknown-warning-option")
            .cxxflag("-Wno-unknown-warning-option")
            // Clang 15 workaround for `ch_compile.cpp`
            .cxxflag("-Wno-unqualified-std-cast-call");
    }

    let built_dir = hs_cmake.build().to_path_buf();

    println!("cargo:rustc-link-search=native={}/lib", built_dir.display());
    if cfg!(feature = "chimera") {
        println!(
            "cargo:rustc-link-search=static={}/build/lib",
            built_dir.display()
        );
    }
    println!("cargo:rustc-link-lib=static=hs");

    #[cfg(feature = "generate-bindings")]
    {
        use bindgen::callbacks::{IntKind, ItemInfo, ParseCallbacks};
        use std::path::Path;
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
        println!("cargo:rerun-if-changed={}/hs.h", manifest_dir.display());

        /// Bindgen provides hooks for user-defined callbacks to change the mapping between C and Rust types.
        /// While it is good at ascertaining types by default, libraries may have specific invariants
        /// that bindgen couldn't possibly know about.
        ///
        /// This [`ParseCallbacks`] provides an ergonomic way of overriding the chosen Rust integer type for variables.
        #[derive(Debug)]
        struct ForceInts<const N: usize>([&'static str; N], IntKind);
        impl<const N: usize> ParseCallbacks for ForceInts<N> {
            fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
                self.0.contains(&name).then_some(self.1)
            }
        }
        /// A [`ParseCallbacks`] to rename a bindgen-generated name.
        #[derive(Debug)]
        struct ForceRename(&'static str, &'static str);
        impl ParseCallbacks for ForceRename {
            fn generated_name_override(&self, item_info: ItemInfo<'_>) -> Option<String> {
                (item_info.name == self.0).then(|| self.1.to_string())
            }
        }

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let include_dir = out_dir.join("include");

        // This is the shared configuration we use when compiling either Hyperscan or Chimera.
        let base_builder = bindgen::Builder::default()
            .header("hs.h")
            .use_core()
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .clang_args(&["-x", "c++", "-std=c++11"])
            .clang_arg(format!("-I{}", include_dir.display()));

        // These are Hyperscan-specific configurations, as well as tweaks to generate more accurate bindings.
        let hs_builder = base_builder
            .clone()
            .allowlist_type("^hs_.+")
            .allowlist_function("^hs_.+")
            .allowlist_var("^HS_.+")
            // Expose `free` from the libc linked by Hyperscan. We use this instead of pulling in
            // the `libc` crate to ensure that we aren't mixing and matching malloc/free between linked C libraries
            // See: https://github.com/VectorCamp/vectorscan/blob/d29730e1cb9daaa66bda63426cdce83505d2c809/src/alloc.c#L39
            // Note: we rename it here for more clarity in the bindings.
            .parse_callbacks(Box::new(ForceRename("free", "libc_free")))
            .allowlist_function("^libc_free$")
            .must_use_type("hs_error_t")
            // An EXT_FLAG is an ULL, but bindgen chooses u32
            .parse_callbacks(Box::new(ForceInts(
                [
                    "HS_EXT_FLAG_MIN_OFFSET",
                    "HS_EXT_FLAG_MAX_OFFSET",
                    "HS_EXT_FLAG_MIN_LENGTH",
                    "HS_EXT_FLAG_EDIT_DISTANCE",
                    "HS_EXT_FLAG_HAMMING_DISTANCE",
                ],
                IntKind::U64,
            )))
            // bindgen defaults to 0_u32, but error codes are i32
            .parse_callbacks(Box::new(ForceInts(["HS_SUCCESS"], IntKind::I32)))
            // HS_VERSION_STRING makes bindgen output non-deterministic because it includes the current calendar date
            .blocklist_item("HS_VERSION_STRING");
        let dest_file = out_dir.join("bindings_hs.rs");
        hs_builder
            .generate()
            .unwrap()
            .write_to_file(&dest_file)
            .unwrap();
        println!("cargo:warning=wrote Vectorscan bindings to {:?}", dest_file);

        #[cfg(feature = "chimera")]
        {
            // These are Chimera-specific configurations, which are identical to their Hyperscan counterparts
            // except for `hs` being replaced by `ch` in names.
            let ch_builder = base_builder
                .clone()
                .allowlist_type("^ch_.+")
                .allowlist_function("^ch_.+")
                .allowlist_var("^CH_.+")
                // Expose `free` from the libc linked by Hyperscan. We use this instead of pulling in
                // the `libc` crate to ensure that we aren't mixing and matching malloc/free between linked C libraries
                // See: https://github.com/VectorCamp/vectorscan/blob/d29730e1cb9daaa66bda63426cdce83505d2c809/chimera/ch_alloc.c#L40
                // Note: we rename it here for more clarity in the bindings.
                .parse_callbacks(Box::new(ForceRename("free", "libc_free")))
                .allowlist_function("^libc_free$")
                .must_use_type("ch_error_t")
                // bindgen defaults to 0_u32, but error codes are i32
                .parse_callbacks(Box::new(ForceInts(["CH_SUCCESS"], IntKind::I32)))
                .clang_arg("-D__BUILD_CHIMERA__");
            let dest_file = out_dir.join("bindings_ch.rs");
            ch_builder
                .generate()
                .unwrap()
                .write_to_file(&dest_file)
                .unwrap();
            println!("cargo:warning=wrote Chimera bindings to {:?}", dest_file);
        }
    }
}

/// A helper function to shallow fetch a Git repository.
fn fetch_dependency(dep: &Dependency) -> bool {
    fn run(command: &str, args: &[&str]) -> bool {
        Command::new(command)
            .args(args)
            .status()
            .is_ok_and(|exit_status| exit_status.success())
    }
    let base_dir = env::current_dir().unwrap();

    run("mkdir", &["-p", &dep.source_path.to_string_lossy()])
        && env::set_current_dir(&dep.source_path).is_ok()
        && run("git", &["init", "-q"])
        && run("git", &["remote", "add", "origin", &dep.url])
        && run(
            "git",
            &["fetch", "-q", "--depth", "1", "origin", &dep.commit_hash],
        )
        && run("git", &["checkout", "-q", "FETCH_HEAD"])
        && run("rm", &["-rf", ".git"])
        && env::set_current_dir(base_dir).is_ok()
}
