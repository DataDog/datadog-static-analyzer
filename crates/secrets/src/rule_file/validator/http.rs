// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::rule_file::check::RawCheck;
use crate::rule_file::{raw_item, RawSecretStatus, RawSeverity, SingletonMap, TemplateString};
use std::collections::BTreeMap;

raw_item! {
    pub struct RawHttp(pub RawExtension);
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "extension", content = "config")]
pub enum RawExtension {
    #[serde(rename = "simple-request")]
    Simple(RawCfgSimpleRequest),
}

// Simple HTTP Request
////////////////////////////////////////

raw_item! {
    pub struct RawCfgSimpleRequest {
        pub request: RawRequest,
        pub response_handler: RawResponseHandler,
    }

    pub struct RawRequest {
        pub url: TemplateString,
        pub headers: Option<RawHeaders>,
        pub method: RawMethod,
        pub body: Option<RawBody>,
    }

    pub struct RawBody {
        pub data: TemplateString,
        pub content_type: String,
    }

    pub struct RawHeaders(pub BTreeMap<String, TemplateString>);

    pub struct RawResponseHandler {
        pub handler_list: Vec<RawHandler>,
        pub default_result: RawActionReturn,
    }

    pub struct RawHandler {
        pub on_match: SingletonMap<RawCheck>,
        pub action: SingletonMap<RawAction>,
    }

    pub struct RawActionReturn {
        #[serde(rename = "secret")]
        pub status: RawSecretStatus,
        pub severity: RawSeverity,
    }

    pub enum RawAction {
        Return(RawActionReturn),
        #[serde(rename = "validation")]
        ControlFlow(RawControlFlow),
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RawMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RawControlFlow {
    Retry,
    Break,
}
