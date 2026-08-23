// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

//! Product-agnostic path inclusion/exclusion primitives, shared by every product (SAST,
//! secrets, ...) that supports `only-paths`/`ignore-paths` configuration.
//!
//! These are model types only. Each product owns its own YAML representation and converts into
//! these, so that renaming a key in one product's configuration file cannot affect another's.

use crate::model::diff_aware::DiffAware;
use globset::{GlobBuilder, GlobMatcher};
use std::borrow::Borrow;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};

// A pattern for an 'only' or 'ignore' field. The 'glob' field contains a precompiled glob pattern,
// while the 'prefix' field contains a path prefix.
#[derive(Default, Clone)]
pub struct PathPattern {
    pub glob: Option<GlobMatcher>,
    pub prefix: PathBuf,
}

impl DiffAware for PathPattern {
    fn generate_diff_aware_digest(&self) -> String {
        let glob = self
            .glob
            .as_ref()
            .map(|v| v.glob().to_string())
            .unwrap_or("".to_string());
        let prefix = self
            .prefix
            .to_str()
            .map(|v| v.to_string())
            .unwrap_or("".to_string());

        format!("{}:{}", glob, prefix)
    }
}

// Lists of directories and glob patterns to include/exclude from the analysis.
#[derive(Debug, PartialEq, Default, Clone)]
pub struct PathConfig {
    // Analyze only these directories and patterns.
    pub only: Option<Vec<PathPattern>>,
    // Do not analyze any of these directories and patterns.
    pub ignore: Vec<PathPattern>,
}

impl DiffAware for PathConfig {
    fn generate_diff_aware_digest(&self) -> String {
        let only = self
            .only
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|w| w.generate_diff_aware_digest())
                    .collect::<Vec<String>>()
                    .join(",")
            })
            .unwrap_or("".to_string());

        let ignore = self
            .ignore
            .iter()
            .map(|v| v.generate_diff_aware_digest())
            .collect::<Vec<String>>()
            .join(",");

        format!("{}:{}", only, ignore)
    }
}

impl PathPattern {
    pub fn matches(&self, path: &str) -> bool {
        self.glob
            .as_ref()
            .map(|g| g.is_match(path))
            .unwrap_or(false)
            || Path::new(path).starts_with(&self.prefix)
    }
}

impl From<String> for PathPattern {
    fn from(value: String) -> Self {
        PathPattern {
            glob: GlobBuilder::new(&value)
                .literal_separator(true)
                .empty_alternates(true)
                .backslash_escape(true)
                .case_insensitive(true)
                .build()
                .map(|g| g.compile_matcher())
                .ok(),
            prefix: PathBuf::from(value),
        }
    }
}

impl Borrow<str> for PathPattern {
    fn borrow(&self) -> &str {
        self.prefix.to_str().unwrap_or("")
    }
}

impl From<PathPattern> for String {
    fn from(value: PathPattern) -> Self {
        value.prefix.display().to_string()
    }
}

impl PartialEq for PathPattern {
    fn eq(&self, other: &Self) -> bool {
        self.prefix.eq(&other.prefix)
    }
}

impl Debug for PathPattern {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let glob_str = if self.glob.is_some() {
            "Some(<opaque>)"
        } else {
            "None"
        };
        f.debug_struct("PathPattern")
            .field("prefix", &self.prefix)
            .field("glob", &glob_str)
            .finish()
    }
}

impl PathConfig {
    pub fn allows_file(&self, file_name: &str) -> bool {
        !self.ignore.iter().any(|pattern| pattern.matches(file_name))
            && match &self.only {
                None => true,
                Some(only) => only.iter().any(|pattern| pattern.matches(file_name)),
            }
    }
}
