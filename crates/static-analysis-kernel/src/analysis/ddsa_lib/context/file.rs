// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use crate::analysis::ddsa_lib::context::file_go::FileContextGo;

#[derive(Debug, Default)]
pub struct FileContext {
    // Supported file contexts:
    go: Option<FileContextGo>,
}

impl FileContext {
    // Returns a mutable reference to the [`FileContextGo`] owned by this `FileContext`, if it exists.
    pub fn go_mut(&mut self) -> Option<&mut FileContextGo> {
        self.go.as_mut()
    }

    // Returns a reference to the [`FileContextGo`] owned by this `FileContext`, if it exists.
    pub fn go(&self) -> Option<&FileContextGo> {
        self.go.as_ref()
    }

    // Assigns the [`FileContextGo`] to this `FileContext`, returning the old value, if it exists.
    pub fn set_go(&mut self, file_ctx_go: FileContextGo) -> Option<FileContextGo> {
        Option::replace(&mut self.go, file_ctx_go)
    }
}
