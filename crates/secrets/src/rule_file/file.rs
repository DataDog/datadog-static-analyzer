// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule_file::matcher::RawMatcher;
use crate::rule_file::raw_struct;
use crate::rule_file::validator::RawValidator;

raw_struct! {
    /// The intermediate representation of a rule, deserialized directly from a file format.
    //
    // NOTE: The deserialization process also performs validation. While it's not ideal to mix concerns
    //       like this, `serde_yaml` does not expose line/col location of deserialized entities
    //       outside of its error handler. Thus, in order to provide helpful error messages when
    //       invalid input is received, we perform the validation here.
    pub struct RawRuleFile {
        pub schema_version: SchemaVersion,
        // Metadata
        pub id: String,
        pub description: Option<String>,
        pub short_description: Option<String>,
        // Rule logic
        pub matcher: RawMatcher,
        pub validator: RawValidator,
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaVersion {
    V1,
}

#[cfg(test)]
mod tests {
    use crate::rule_file::RawRuleFile;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Non-recursively searches the given `testdata` subdirectory and returns rule file paths.
    fn get_rule_files(subdirectory: &str) -> Vec<PathBuf> {
        let dir = fs::read_dir(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/rule_file/testdata")
                .join(subdirectory),
        )
        .expect("should have been able to read directory");

        dir.filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.is_file() && path.extension().is_some_and(|ext| ext == "yml")).then_some(path)
        })
        .collect::<Vec<_>>()
    }
    /// Ensures that the corpus of valid rule files can be parsed.
    #[test]
    fn parse_valid_rules() {
        for file_path in get_rule_files("valid") {
            let file_name = file_path.file_name().unwrap();
            let contents = fs::read_to_string(&file_path)
                .expect(&format!("should be able to read {:?}", file_name));
            let parsed = serde_yaml::from_str::<RawRuleFile>(&contents);
            if let Err(err) = parsed {
                panic!("unable to parse valid test rule {:?}: {}", file_name, err);
            }
        }
    }
}
