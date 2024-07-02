use crate::model::config_file::{BySubtree, ConfigFile, SplitPath};
use crate::model::diff_aware::DiffAware;
use std::collections::HashMap;

type Argument = (String, String);

#[derive(Clone)]
// Used to extract rule arguments in the analyzer.
pub struct ArgumentProvider {
    by_rule: HashMap<String, BySubtree<Vec<Argument>>>,
}

impl DiffAware for ArgumentProvider {
    fn generate_diff_aware_digest(&self) -> String {
        let mut arguments_config = self
            .by_rule
            .iter()
            .flat_map(|(rule, subtree)| {
                subtree.iter().flat_map(|(st, v)| {
                    st.into_iter().flat_map(|path_component| {
                        v.iter()
                            .map(|(arg1, arg2)| {
                                format!(
                                    "{}:{}:{}:{}",
                                    rule.clone(),
                                    &path_component.generate_diff_aware_digest(),
                                    arg1.clone(),
                                    arg2.clone()
                                )
                            })
                            .collect::<Vec<String>>()
                    })
                })
            })
            .collect::<Vec<String>>();

        // Make sure that regardless of the order of the arguments, we have the same
        // string run after run.
        arguments_config.sort();

        arguments_config.join(",")
    }
}

impl ArgumentProvider {
    pub fn new() -> ArgumentProvider {
        ArgumentProvider {
            by_rule: HashMap::new(),
        }
    }

    pub fn from(config: &ConfigFile) -> Self {
        let mut provider = ArgumentProvider::new();
        for (ruleset_name, ruleset_cfg) in &config.rulesets {
            for (rule_shortname, rule_cfg) in &ruleset_cfg.rules {
                for (arg_name, arg_values) in &rule_cfg.arguments {
                    let rule_name = format!("{}/{}", ruleset_name, rule_shortname);
                    for (prefix, value) in arg_values.iter() {
                        provider.add_argument(
                            &rule_name,
                            &prefix.into_iter().cloned().collect(),
                            arg_name,
                            value,
                        );
                    }
                }
            }
        }
        provider
    }

    pub fn add_argument(&mut self, rule_name: &str, path: &SplitPath, argument: &str, value: &str) {
        let by_subtree = self.by_rule.entry(rule_name.to_string()).or_default();
        match by_subtree.get_mut(path) {
            None => {
                by_subtree.insert(path, vec![(argument.to_string(), value.to_string())]);
            }
            Some(v) => {
                v.push((argument.to_string(), value.to_string()));
            }
        };
    }

    /// Returns the arguments that apply to the given file and the given rule.
    pub fn get_arguments(&self, filename: &SplitPath, rulename: &str) -> HashMap<String, String> {
        let mut out = HashMap::new();
        if let Some(by_prefix) = self.by_rule.get(rulename) {
            for args in by_prefix.prefix_iter(filename) {
                // Longer prefixes appear last, so they'll override arguments from shorter prefixes.
                if let Some(value) = args.value() {
                    out.extend(value.iter().cloned());
                }
            }
        }
        out
    }
}

impl Default for ArgumentProvider {
    fn default() -> Self {
        ArgumentProvider::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::config_file::split_path;
    use std::collections::HashMap;

    #[test]
    fn test_argument_provider_returns_arg_for_default_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", &split_path("/"), "arg", "value");

        let expected = HashMap::from([("arg".to_string(), "value".to_string())]);
        assert_eq!(
            argument_provider.get_arguments(&split_path("a"), "rule"),
            expected
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("b/c"), "rule"),
            expected
        );
    }

    #[test]
    fn test_argument_provider_returns_arg_for_path_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", &split_path("a/b/c"), "arg", "value");

        let expected = HashMap::from([("arg".to_string(), "value".to_string())]);
        assert!(argument_provider
            .get_arguments(&split_path("a"), "rule")
            .is_empty());
        assert!(argument_provider
            .get_arguments(&split_path("a/b"), "rule")
            .is_empty());
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b/c"), "rule"),
            expected
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b/c/d"), "rule"),
            expected
        );
    }

    #[test]
    fn test_argument_provider_returns_arg_for_longest_path_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", &split_path("a/b"), "arg", "first");
        argument_provider.add_argument("rule", &split_path("a/b/c"), "arg", "second");

        let expected_first = HashMap::from([("arg".to_string(), "first".to_string())]);
        let expected_second = HashMap::from([("arg".to_string(), "second".to_string())]);
        assert!(argument_provider
            .get_arguments(&split_path("a"), "rule")
            .is_empty());
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b"), "rule"),
            expected_first
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b/c"), "rule"),
            expected_second
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b/c/d"), "rule"),
            expected_second
        );
    }

    #[test]
    fn test_argument_provider_returns_multiple_args_in_path() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", &split_path("a"), "arg1", "first_1");
        argument_provider.add_argument("rule", &split_path("a"), "arg2", "first_2");
        argument_provider.add_argument("rule", &split_path("a/b"), "arg3", "first_3");
        argument_provider.add_argument("rule", &split_path("a/b/c"), "arg1", "second_1");

        assert_eq!(
            argument_provider.get_arguments(&split_path("a"), "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b"), "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b/c"), "rule"),
            HashMap::from([
                ("arg1".to_string(), "second_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
    }

    #[test]
    fn test_argument_provider_is_independent_from_insertion_order() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", &split_path("a/b/c"), "arg1", "second_1");
        argument_provider.add_argument("rule", &split_path("a"), "arg2", "first_2");
        argument_provider.add_argument("rule", &split_path("a/b"), "arg3", "first_3");
        argument_provider.add_argument("rule", &split_path("a"), "arg1", "first_1");

        assert_eq!(
            argument_provider.get_arguments(&split_path("a"), "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b"), "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments(&split_path("a/b/c"), "rule"),
            HashMap::from([
                ("arg1".to_string(), "second_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
    }

    #[test]
    fn test_argument_generate_diff_aware() {
        let mut argument_provider1 = ArgumentProvider::new();
        argument_provider1.add_argument("rule", &split_path("a/b/c"), "arg1", "second_1");
        argument_provider1.add_argument("rule", &split_path("a"), "arg2", "first_2");

        assert_eq!(
            "rule:a:arg1:second_1,rule:a:arg2:first_2,rule:b:arg1:second_1,rule:c:arg1:second_1",
            argument_provider1.generate_diff_aware_digest()
        );
        let mut argument_provider2 = ArgumentProvider::new();
        argument_provider2.add_argument("rule", &split_path("a"), "arg2", "first_2");
        argument_provider2.add_argument("rule", &split_path("a/b/c"), "arg1", "second_1");

        assert_eq!(
            argument_provider1.generate_diff_aware_digest(),
            argument_provider2.generate_diff_aware_digest()
        );
    }
}
