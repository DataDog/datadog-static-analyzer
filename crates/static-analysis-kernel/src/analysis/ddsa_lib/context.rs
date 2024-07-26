// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

mod file;
pub use file::FileContext;
pub(crate) mod file_go;
pub use file_go::FileContextGo;
pub(crate) mod file_tf;
pub use file_tf::FileContextTerraform;
pub(crate) mod file_js;
pub use file_js::FileContextJavaScript;
mod root;
pub use root::RootContext;
mod rule;
pub use rule::RuleContext;
pub(crate) mod ts_lang;
pub use ts_lang::TsLanguageContext;
