// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged, rename_all = "kebab-case")]
pub enum StringsOrInts {
    Strings(Vec<String>),
    Integers(Vec<isize>),
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged, rename_all = "kebab-case")]
pub enum StringOrInt {
    String(String),
    Integer(isize),
}

impl Display for StringOrInt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            StringOrInt::String(str) => write!(f, "{}", str),
            StringOrInt::Integer(int) => write!(f, "{}", int),
        }
    }
}
