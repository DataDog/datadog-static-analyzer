// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

// TODO: should there be a builder trait? probably too premature
// idea with builder trait is that they take incoming rules and spit out a Vec<Matcher>.
// this lets the builder itself determine whether a single matcher can handle everything (e.g. Hyperscan, globset)
// or if there needs to be more than one (e.g. pcre2)

pub struct HyperscanBuilder {}
