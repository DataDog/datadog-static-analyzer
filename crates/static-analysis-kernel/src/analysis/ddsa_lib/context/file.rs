// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use super::{file_js::FileContextJavaScript, FileContextTerraform};
use crate::analysis::ddsa_lib::context::file_go::FileContextGo;

#[derive(Debug, Default)]
pub struct FileContext {
    // Supported file contexts:
    go: Option<FileContextGo>,
    terraform: Option<FileContextTerraform>,
    javascript: Option<FileContextJavaScript>,
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

    /// Returns a mutable reference to the [`FileContextTerraform`] owned by this `FileContext`, if it exists.
    pub fn tf_mut(&mut self) -> Option<&mut FileContextTerraform> {
        self.terraform.as_mut()
    }

    /// Returns a reference to the [`FileContextTerraform`] owned by this `FileContext`, if it exists.
    pub fn tf(&self) -> Option<&FileContextTerraform> {
        self.terraform.as_ref()
    }

    /// Assigns the [`FileContextTerraform`] to this `FileContext`, returning the old value, if it exists.
    pub fn set_tf(&mut self, file_ctx_tf: FileContextTerraform) -> Option<FileContextTerraform> {
        self.terraform.replace(file_ctx_tf)
    }

    /// Returns a mutable reference to the [`FileContextJavaScript`] owned by this `FileContext`, if it exists.
    pub fn js_mut(&mut self) -> Option<&mut FileContextJavaScript> {
        self.javascript.as_mut()
    }

    /// Returns a reference to the [`FileContextJavaScript`] owned by this `FileContext`, if it exists.
    pub fn js(&self) -> Option<&FileContextJavaScript> {
        self.javascript.as_ref()
    }

    /// Assigns the [`FileContextJavaScript`] to this `FileContext`, returning the old value, if it exists.
    pub fn set_js(&mut self, file_ctx_js: FileContextJavaScript) -> Option<FileContextJavaScript> {
        self.javascript.replace(file_ctx_js)
    }
}
