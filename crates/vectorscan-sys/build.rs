// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::env;
use std::ffi::OsStr;
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

/// This build script provides the `hs` library, a high-performance multiple regex matching library.
///
/// On Linux and macOS, this builds [Vectorscan](https://github.com/VectorCamp/vectorscan), a fork of Hyperscan.
/// On Windows x86_64, this builds [Hyperscan](https://github.com/intel/hyperscan).
///
/// NOTE: Building Hyperscan is a temporary compatibility strategy until Vectorscan supports Windows.
/// See: https://github.com/VectorCamp/vectorscan/issues/207
///
/// By default, the Hyperscan tools (fuzz, hsbench, hscheck, hscollider, hsdump) binaries are not built,
/// but can be with feature `hs_tools`.
///
/// This script can also build [Chimera](https://intel.github.io/hyperscan/dev-reference/chimera.html), which
/// is an officially-supported regex engine that functions as a hybrid between Hyperscan and PCRE,
/// with full support for PCRE syntax. While disabled by default, Chimera can be activated with feature `chimera`.
///
/// Lastly, `bindgen` is used to automatically create low-level bindings between Hyperscan's C ABI and Rust.
/// These bindings are pre-generated in the `src` folder for convenience. However, library consumers can
/// freshly generate bindings with the `generate-bindings` feature.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let hs_dependency = if cfg!(target_family = "windows") {
        Dependency::new(
            "hyperscan-5.4.2",
            "https://github.com/intel/hyperscan",
            "bc3b191ab56055e8560c7cdc161c289c4d76e3d2",
        )
    } else {
        Dependency::new(
            "vectorscan-5.4.11",
            "https://github.com/VectorCamp/vectorscan",
            "d29730e1cb9daaa66bda63426cdce83505d2c809",
        )
    };
    let pcre_dependency = Dependency::new(
        "pcre-8.45",
        "https://github.com/luvit/pcre",
        "5c78f7d5d7f41bdd4be4867ef3a1030af3e973e3",
    );

    let needs_pcre = cfg!(any(feature = "chimera", feature = "hs_tools"));

    let dependencies = if needs_pcre {
        vec![&hs_dependency, &pcre_dependency]
    } else {
        vec![&hs_dependency]
    };

    for dependency in dependencies {
        assert!(fetch_dependency(dependency));
    }

    // A bit of a hacky workaround for the lack of a CMake option:
    // The `tools` folder is only compiled if the CMakeLists.txt file is detected:
    // https://github.com/VectorCamp/vectorscan/blob/d29730e1cb9daaa66bda63426cdce83505d2c809/CMakeLists.txt#L1199-L1200
    #[rustfmt::skip]
    #[cfg(not(feature = "hs_tools"))]
    assert!(run("rm", &["-f", &hs_dependency.source_path.join("tools/CMakeLists.txt").to_string_lossy()]));

    let mut hs_cmake = cmake::Config::new(hs_dependency.source_path);
    hs_cmake
        // Override Vectorscan's default build configuration.
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_BENCHMARKS", "OFF");
    if needs_pcre {
        hs_cmake.define("PCRE_SOURCE", &pcre_dependency.source_path);
    }

    match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "windows" => {
            let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
            let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
            match (target_env.as_str(), target_arch.as_str()) {
                ("msvc", "x86_64") => {
                    // cmake-rs seems to strip the `/EHsc` flag that CMake uses by default
                    // See: https://github.com/rust-lang/cmake-rs/issues/198
                    hs_cmake.cflag("/EHsc").cxxflag("/EHsc");
                }
                (env, "x86_64") => unimplemented!("unsupported windows env: `{}`", env),
                (env, arch) => panic!("unsupported windows configuration: `{}` `{}`", env, arch),
            }
        }
        "macos" => println!("cargo:rustc-link-lib=c++"),
        "linux" => println!("cargo:rustc-link-lib=stdc++"),
        _ => println!("cargo:rustc-link-lib=stdc++"),
    }

    #[cfg(feature = "chimera")]
    {
        hs_cmake.define("BUILD_CHIMERA", "ON");

        #[cfg(not(target_env = "msvc"))]
        hs_cmake
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
        use bindgen::callbacks::{IntKind, ParseCallbacks};
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
            // Delegate to the `free` implementation Hyperscan uses.
            // See: https://github.com/VectorCamp/vectorscan/blob/d29730e1cb9daaa66bda63426cdce83505d2c809/src/alloc.c#L39
            // Note: we rename it here for more clarity in the bindings.
            .allowlist_function("^free$")
            .raw_line("pub use free as hs_misc_free;")
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
        let dest_file = if cfg!(target_family = "windows") {
            out_dir.join("hyperscan_bindings_hs.rs")
        } else {
            out_dir.join("vectorscan_bindings_hs.rs")
        };
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
                // Delegate to the `free` implementation Hyperscan uses.
                // See: https://github.com/VectorCamp/vectorscan/blob/d29730e1cb9daaa66bda63426cdce83505d2c809/chimera/ch_alloc.c#L40
                // Note: we rename it here for more clarity in the bindings.
                .allowlist_function("^free$")
                .raw_line("pub use free as ch_misc_free;")
                .must_use_type("ch_error_t")
                // bindgen defaults to 0_u32, but error codes are i32
                .parse_callbacks(Box::new(ForceInts(["CH_SUCCESS"], IntKind::I32)))
                .clang_arg("-D__BUILD_CHIMERA__");
            let dest_file = if cfg!(target_family = "windows") {
                out_dir.join("hyperscan_bindings_ch.rs")
            } else {
                out_dir.join("vectorscan_bindings_ch.rs")
            };
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
    let base_dir = env::current_dir().unwrap();

    run("rm", &["-rf", &dep.source_path.to_string_lossy()])
        && run("mkdir", &["-p", &dep.source_path.to_string_lossy()])
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

/// Builds and executes a [`Command`] with the given arguments.
fn run<T: AsRef<OsStr>>(command: &str, args: &[T]) -> bool {
    Command::new(command)
        .args(args)
        .status()
        .is_ok_and(|exit_status| exit_status.success())
}
