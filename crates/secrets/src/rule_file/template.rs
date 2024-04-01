// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use serde::de::{Error, Unexpected};
use serde::{Deserialize, Deserializer};
use std::fmt::{Debug, Display, Formatter};

use TemplateStringError::{Expression, Parse};

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum TemplateStringError {
    #[error("invalid expression at offset {offset}: {msg}")]
    Expression { offset: usize, msg: String },
    #[error("syntax error at offset {offset}. unexpected `{unexpected}`")]
    Parse { offset: usize, unexpected: String },
    #[error("expected single template variable. got: `{0}`")]
    NotSingleVariable(String),
    #[error("variable {0} not defined")]
    UndefinedVariable(String),
}

/// A string-like type that may contain template variables.
///
/// Template variables are embedded into marked up text and are syntactically defined by
/// wrapping text within `${{` and `}}`.
///
/// In the below example, `${{ TOKEN }}` is a template variable, and its value is looked up
/// from a provider at runtime.
/// ```rust
/// # use secrets::rule_file::TemplateString;
/// # use std::collections::HashMap;
///
/// let hm = HashMap::from([("TOKEN", "12345678")]);
/// // The variables provider can be any function that returns a string, given an input string.
/// // In this example, a simple key-value lookup is the provider.
/// let variables_provider = |var: &str| hm.get(var).copied();
///
/// // `TOKEN` is a template variable
/// let input = TemplateString::try_parse("https://example.com/auth?token=${{ TOKEN }}").unwrap();
/// let evaluated = input.try_evaluate(&variables_provider).unwrap();
/// assert_eq!(evaluated, "https://example.com/auth?token=12345678");
/// ```
#[derive(Clone, Default, Eq, PartialEq, Hash)]
pub struct TemplateString(String, Vec<Fragment>);

impl Debug for TemplateString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TemplateString(\"{}\")", self.0)
    }
}
impl Display for TemplateString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A function that provides the value of a given variable.
pub type DynFnVariableProvider<'a> = dyn Fn(&'a str) -> Option<&'a str> + 'a;

impl TemplateString {
    #[rustfmt::skip]
    /// Attempts to parse a string as a `TemplateString`, validating that any defined template
    /// variables are correctly specified.
    pub fn try_parse(input: impl Into<String>) -> Result<Self, TemplateStringError> {
        let input = input.into();
        // Calculates the byte offset of a slice, given its parent.
        let offset_of =
            |slice: &str| -> usize { slice.as_ptr() as usize - input.as_ptr() as usize };

        let mut fragments = Vec::<Fragment>::new();
        let mut next = input.as_str();
        while let Some((outer_prefix, outer_suffix)) = next.split_once("${{") {
            if !outer_prefix.is_empty() {
                fragments.push(Fragment::Literal(outer_prefix.to_string()));
            }

            if let Some((inner_prefix, inner_suffix)) = outer_suffix.split_once("}}") {
                // Trim outside whitespace
                let trimmed = inner_prefix.trim();
                if trimmed.is_empty() {
                    return Err(Expression { offset: offset_of(outer_suffix), msg: "empty evaluation".to_string() });
                }
                for (inner_idx, ch) in trimmed.char_indices() {
                    if matches!(ch, '$' | '{') || char::is_whitespace(ch) {
                        return Err(Parse { offset: offset_of(trimmed) + inner_idx, unexpected: ch.to_string() });
                    }
                }
                fragments.push(Fragment::Variable(trimmed.to_string()));
                next = inner_suffix;

            } else {
                return Err(Expression { offset: offset_of(outer_suffix), msg: "unclosed evaluation".to_string() });
            }
        }
        if !next.is_empty() {
            fragments.push(Fragment::Literal(next.to_string()));
        }

        Ok(Self(input, fragments))
    }

    /// Given a `variables_provider` function that maps from a `&str` key to a `&str` value,
    /// looks up and inlines all template variable values into a final, interpolated string.
    pub fn try_evaluate<'a>(
        &'a self,
        variables_provider: &DynFnVariableProvider<'a>,
    ) -> Result<String, TemplateStringError> {
        let mut string = String::new();
        for fragment in &self.1 {
            match fragment {
                Fragment::Literal(s) => string.push_str(s.as_str()),
                Fragment::Variable(var) => {
                    let value = variables_provider(var)
                        .ok_or_else(|| TemplateStringError::UndefinedVariable(var.clone()))?;
                    string.push_str(value);
                }
            }
        }
        Ok(string)
    }

    /// Returns a slice to the raw string, potentially including unprocessed template variables.
    pub fn raw(&self) -> &str {
        self.0.as_str()
    }

    /// Returns `true` if this string uses a template variable.
    pub fn is_dynamic(&self) -> bool {
        self.1.iter().any(|f| matches!(f, Fragment::Variable(_)))
    }
}

impl<'de> Deserialize<'de> for TemplateString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str: String = Deserialize::deserialize(deserializer)?;
        TemplateString::try_parse(str).map_err(|err| match err {
            Expression { msg, .. } => D::Error::custom(msg),
            Parse { unexpected, .. } => {
                D::Error::invalid_value(Unexpected::Str(&unexpected), &"a valid character")
            }
            TemplateStringError::UndefinedVariable(_)
            | TemplateStringError::NotSingleVariable(_) => unreachable!(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum Fragment {
    Literal(String),
    Variable(String),
}

/// A subtype of a [`TemplateString`] that represents exactly one variable.
///
/// # Examples
/// ```rust
/// # use secrets::rule_file::{TemplateStringError, TemplateVar};
///
/// let var = TemplateVar::try_parse("${{ http.response.status }}").unwrap();
/// assert_eq!(var.name(), "http.response.status");
/// ```
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct TemplateVar(Fragment);

impl Debug for TemplateVar {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "TemplateVar(\"{}\")", self.name())
    }
}
impl Display for TemplateVar {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl TemplateVar {
    /// Returns the name of the variable. For example:
    /// ```text
    /// http.response.status
    /// ```
    pub fn name(&self) -> &str {
        match &self.0 {
            Fragment::Variable(s) => s.as_str(),
            Fragment::Literal(_) => unreachable!(),
        }
    }
}

impl TemplateVar {
    pub fn try_parse(input: impl Into<String>) -> Result<Self, TemplateStringError> {
        let input = input.into();
        let template_var = TemplateString::try_parse(input.trim())?;
        let is_single_var = template_var
            .1
            .first()
            .is_some_and(|fragment| matches!(fragment, Fragment::Variable(_)))
            && template_var.1.len() == 1;
        if !is_single_var {
            Err(TemplateStringError::NotSingleVariable(
                template_var.raw().to_string(),
            ))
        } else {
            let fragment = template_var.1.into_iter().next().expect("len should be 1");
            Ok(Self(fragment))
        }
    }
}

impl<'de> Deserialize<'de> for TemplateVar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let template_str: TemplateString = Deserialize::deserialize(deserializer)?;
        TemplateVar::try_parse(template_str.raw()).map_err(|err| match err {
            TemplateStringError::NotSingleVariable(_) => {
                D::Error::invalid_type(Unexpected::NewtypeStruct, &"a template variable")
            }
            _ => unreachable!(),
        })
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use crate::rule_file::template::{Fragment, TemplateString, TemplateStringError};
    use std::collections::HashMap;
    use crate::rule_file::TemplateVar;

    fn literal(str: &str) -> Fragment {
        Fragment::Literal(str.to_string())
    }
    fn variable(str: &str) -> Fragment {
        Fragment::Variable(str.to_string())
    }

    #[test]
    fn parse_variables() {
        assert_eq!(
            TemplateString::try_parse("The quick brown fox jumps over the lazy dog").unwrap().1,
            vec![literal("The quick brown fox jumps over the lazy dog")]
        );
        assert_eq!(
            TemplateString::try_parse("The quick ${{brown}} fox jumps over the lazy ${{dog}}").unwrap().1,
            vec![literal("The quick "), variable("brown"), literal(" fox jumps over the lazy "), variable("dog")]
        );
        assert_eq!(
            TemplateString::try_parse("${{quick}}").unwrap().1,
            vec![variable("quick")]
        );
        assert_eq!(
            TemplateString::try_parse("${{  jumps  }}${{over }}${{ the}}").unwrap().1,
            vec![variable("jumps"), variable("over"), variable("the")]
        );
        assert_eq!(
            TemplateString::try_parse("${ single }${ braces }").unwrap().1,
            vec![literal("${ single }${ braces }")]
        );
        assert_eq!(TemplateString::try_parse("${{  }}").unwrap_err(), TemplateStringError::Expression { offset: 3, msg: "empty evaluation".to_string() });
        assert_eq!(TemplateString::try_parse("The ${{ $ }}").unwrap_err(), TemplateStringError::Parse { offset: 8, unexpected: "$".to_string() });
        assert_eq!(TemplateString::try_parse("The ${{{ quick }}").unwrap_err(), TemplateStringError::Parse { offset: 7, unexpected: "{".to_string() });
        assert_eq!(TemplateString::try_parse("The quick ${{brown").unwrap_err(), TemplateStringError::Expression { offset: 13, msg: "unclosed evaluation".to_string() });
        assert_eq!(TemplateString::try_parse("The ${{lazy dog}}").unwrap_err(), TemplateStringError::Parse { offset: 11, unexpected: " ".to_string() });
    }

    #[test]
    fn evaluate_variables() {
        let hm1 = HashMap::from([("quick", "lazy"), ("lazy", "")]);
        let int_str =
            TemplateString::try_parse("The ${{quick}} fox jumps over the ${{ lazy }} dog").unwrap();
        let provider1 = |key: &str| -> Option<&str> { hm1.get(key).copied() };
        assert_eq!(int_str.try_evaluate(&provider1).unwrap().as_str(), "The lazy fox jumps over the  dog");
        let provider2 = |_key: &str| -> Option<&str> { None };
        assert!(matches!(
            int_str.try_evaluate(&provider2).unwrap_err(),
            TemplateStringError::UndefinedVariable(v) if v == "quick".to_string()
        ));
    }

    /// Asserts that the original string without interpolation is accessible
    #[test]
    fn raw_string() {
        let raw_string = "The quick ${{brown}} fox jumps over the lazy ${{dog}}";
        let ts = TemplateString::try_parse(raw_string).unwrap();
        assert_eq!(ts.raw(), raw_string);
    }

    #[test]
    fn var_whitespace_ignored() {
        let raw_string = "  ${{ http.response.status }}";
        let tv = TemplateVar::try_parse(raw_string).unwrap();
        assert_eq!(tv.name(), "http.response.status");
    }

    #[test]
    fn var_no_extra_text() {
        let raw_string = r#"{"value": ${{ http.response.status }}}"#;
        let tv = TemplateVar::try_parse(raw_string);
        assert!(matches!(tv.unwrap_err(), TemplateStringError::NotSingleVariable(_)));
    }

    #[test]
    fn var_only_one() {
        let raw_string = "${{ http.response.status }}${{ http.response.body }}";
        let tv = TemplateVar::try_parse(raw_string);
        assert!(matches!(tv.unwrap_err(), TemplateStringError::NotSingleVariable(_)));
    }
}
