// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Information about a project to compile with CMake
struct Dependency {
    /// A pretty name for the dependency
    name: &'static str,
    /// The source directory of the dependency's source code
    src_dir: PathBuf,
    /// A filename that should be present if the git submodule was initialized
    probe_filename: &'static str,
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let vendor_dir = manifest_dir.join("vendor");
    println!("cargo:rerun-if-changed={}", vendor_dir.display());
    let hs_dep = Dependency {
        name: "vectorscan",
        src_dir: vendor_dir.join("vectorscan"),
        probe_filename: "LICENSE",
    };
    let pcre_dep = Dependency {
        name: "pcre",
        src_dir: vendor_dir.join("pcre"),
        probe_filename: "LICENCE",
    };

    let dependencies = if cfg!(feature = "chimera") {
        vec![&hs_dep, &pcre_dep]
    } else {
        vec![&hs_dep]
    };

    for dependency in dependencies {
        if !dependency.src_dir.join(dependency.probe_filename).exists() {
            println!("cargo:warning=retrieving {} git submodule", dependency.name);
            assert!(Command::new("git")
                .args([
                    "submodule",
                    "update",
                    "--init",
                    "--recommend-shallow",
                    dependency.src_dir.to_str().unwrap()
                ])
                .status()
                .is_ok_and(|exit_status| exit_status.success()));
        }
    }

    match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "windows" => panic!("Vectorscan cannot be compiled for os: windows"),
        "macos" => println!("cargo:rustc-link-lib=c++"),
        "linux" => println!("cargo:rustc-link-lib=stdc++"),
        _ => println!("cargo:rustc-link-lib=stdc++"),
    }

    let mut hs_cmake = cmake::Config::new(&hs_dep.src_dir);
    hs_cmake
        // Override Vectorscan's defaults
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_BENCHMARKS", "OFF");

    #[cfg(feature = "chimera")]
    {
        hs_cmake
            .define("PCRE_SOURCE", pcre_dep.src_dir.as_os_str())
            .define("BUILD_CHIMERA", "ON")
            // Clang 15 bumps "unqualified-std-cast-call" from a warning to an error. Chimera has libraries that
            // use unqualified `std::move`, so we silence them to prevent a build failure.
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
        println!("cargo:rerun-if-changed={}/hs.h", manifest_dir.display());

        /// A callback to allow overriding bindgen's chosen Rust integer type for variables
        #[derive(Debug)]
        struct ForceInts<const N: usize>([&'static str; N], IntKind);
        impl<const N: usize> ParseCallbacks for ForceInts<N> {
            fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
                self.0.contains(&name).then_some(self.1)
            }
        }

        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let include_dir = out_dir.join("include");

        let base_builder = bindgen::Builder::default()
            .header("hs.h")
            .use_core()
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .clang_args(&["-x", "c++", "-std=c++11"])
            .clang_arg(format!("-I{}", include_dir.display()));

        let hs_builder = base_builder
            .clone()
            .allowlist_type("^hs_.+")
            .allowlist_function("^hs_.+")
            .allowlist_var("^HS_.+")
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
            let ch_builder = base_builder
                .clone()
                .allowlist_type("^ch_.+")
                .allowlist_function("^ch_.+")
                .allowlist_var("^CH_.+")
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
