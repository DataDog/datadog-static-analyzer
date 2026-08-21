// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026 Datadog, Inc.

//! How a configuration was obtained. Product-agnostic: it records where configuration came from,
//! not what any product's configuration says.

#[derive(Debug, Clone)]
pub enum ConfigMethod {
    File,
    RemoteConfiguration,
    RemoteConfigurationWithFile,
}
