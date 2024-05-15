use crate::model::config_file::ConfigFile;
use sequence_trie::SequenceTrie;
use std::collections::HashMap;

type Argument = (String, String);

type ArgumentsByPrefix = SequenceTrie<String, Vec<Argument>>;

#[derive(Clone)]
// Used to extract rule arguments in the analyzer.
pub struct ArgumentProvider {
    by_rule: HashMap<String, ArgumentsByPrefix>,
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
                    for (prefix, value) in &arg_values.by_subtree {
                        provider.add_argument(&rule_name, prefix, arg_name, value);
                    }
                }
            }
        }
        provider
    }

    pub fn add_argument(&mut self, rule_name: &str, path: &str, argument: &str, value: &str) {
        let prefix: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| c.to_string())
            .collect();
        let trie = self.by_rule.entry(rule_name.to_string()).or_default();
        match trie.get_mut(prefix.iter()) {
            None => {
                trie.insert(
                    prefix.iter(),
                    vec![(argument.to_string(), value.to_string())],
                );
            }
            Some(v) => {
                v.push((argument.to_string(), value.to_string()));
            }
        };
    }

    /// Returns the arguments that apply to the given file and the given rule.
    pub fn get_arguments(&self, filename: &str, rulename: &str) -> HashMap<String, String> {
        let mut out = HashMap::new();
        if let Some(by_prefix) = self.by_rule.get(rulename) {
            for args in by_prefix
                .prefix_iter(filename.split('/').filter(|c| !c.is_empty()))
                .filter_map(|x| x.value())
            {
                // Longer prefixes appear last, so they'll override arguments from shorter prefixes.
                out.extend(args.clone());
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
    use std::collections::HashMap;

    #[test]
    fn test_argument_provider_returns_arg_for_default_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "/", "arg", "value");

        let expected = HashMap::from([("arg".to_string(), "value".to_string())]);
        assert_eq!(argument_provider.get_arguments("a", "rule"), expected);
        assert_eq!(argument_provider.get_arguments("b/c", "rule"), expected);
    }

    #[test]
    fn test_argument_provider_returns_arg_for_path_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "a/b/c", "arg", "value");

        let expected = HashMap::from([("arg".to_string(), "value".to_string())]);
        assert!(argument_provider.get_arguments("a", "rule").is_empty());
        assert!(argument_provider.get_arguments("a/b", "rule").is_empty());
        assert_eq!(argument_provider.get_arguments("a/b/c", "rule"), expected);
        assert_eq!(argument_provider.get_arguments("a/b/c/d", "rule"), expected);
    }

    #[test]
    fn test_argument_provider_returns_arg_for_longest_path_prefix() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "a/b", "arg", "first");
        argument_provider.add_argument("rule", "a/b/c", "arg", "second");

        let expected_first = HashMap::from([("arg".to_string(), "first".to_string())]);
        let expected_second = HashMap::from([("arg".to_string(), "second".to_string())]);
        assert!(argument_provider.get_arguments("a", "rule").is_empty());
        assert_eq!(
            argument_provider.get_arguments("a/b", "rule"),
            expected_first
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c", "rule"),
            expected_second
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c/d", "rule"),
            expected_second
        );
    }

    #[test]
    fn test_argument_provider_returns_multiple_args_in_path() {
        let mut argument_provider = ArgumentProvider::new();
        argument_provider.add_argument("rule", "a", "arg1", "first_1");
        argument_provider.add_argument("rule", "a", "arg2", "first_2");
        argument_provider.add_argument("rule", "a/b", "arg3", "first_3");
        argument_provider.add_argument("rule", "a/b/c", "arg1", "second_1");

        assert_eq!(
            argument_provider.get_arguments("a", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c", "rule"),
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
        argument_provider.add_argument("rule", "a/b/c", "arg1", "second_1");
        argument_provider.add_argument("rule", "a", "arg2", "first_2");
        argument_provider.add_argument("rule", "a/b", "arg3", "first_3");
        argument_provider.add_argument("rule", "a", "arg1", "first_1");

        assert_eq!(
            argument_provider.get_arguments("a", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b", "rule"),
            HashMap::from([
                ("arg1".to_string(), "first_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
        assert_eq!(
            argument_provider.get_arguments("a/b/c", "rule"),
            HashMap::from([
                ("arg1".to_string(), "second_1".to_string()),
                ("arg2".to_string(), "first_2".to_string()),
                ("arg3".to_string(), "first_3".to_string())
            ])
        );
    }
}
