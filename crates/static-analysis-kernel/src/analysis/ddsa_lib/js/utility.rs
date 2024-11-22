// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::test_utils::{cfg_test_v8, try_execute};

    #[test]
    fn console_basic_serialization() {
        let mut runtime = cfg_test_v8().deno_core_rt();
        let scope = &mut runtime.handle_scope();
        // NOTE: There are special cases where certain class instances serialize to a different format.
        // These are tested in the `runtime` module, as they might require multiple bridges to be configured.
        let cases: &[(&str, &str)] = &[
            // Single argument
            (r#"{ a: 123, b: "abc" }"#, r#"{"a":123,"b":"abc"}"#),
            ("undefined", "undefined"),
            ("null", "null"),
            ("1234", "1234"),
            ("12.34", "12.34"),
            (r#""A string""#, "A string"),
            ("123456789123456789n", "123456789123456789"),
            ("true", "true"),
            (r#"Symbol("abc")"#, r#"Symbol(abc)"#),
            ("[1, {a: 2}, 3, 4.0]", r#"[1,{"a":2},3,4]"#),
            // Multiple arguments
            (r#"1, "A string", {a: 2}"#, r#"1 A string {"a":2}"#),
        ];

        for &(js_value, expected_serialization) in cases {
            let code = format!("DDSA_Console.stringifyAll({});", js_value);
            let value = try_execute(scope, &code).unwrap();
            assert_eq!(value.to_rust_string_lossy(scope), expected_serialization);
        }
    }
}
