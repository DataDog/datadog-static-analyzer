use crate::analyzers::analyzer::Analyzer;
use crate::model::dependency::Dependency;
use crate::model::ecosystem::Ecosystem;
use crate::model::ecosystem::Ecosystem::Jvm;
use kernel::analysis::tree_sitter::{get_query_nodes, get_tree, get_tree_sitter_language};
use kernel::model::common::Language;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::iter::Map;
use tree_sitter::QueryCapture;

const TREE_SITTER_QUERY_VARIABLES: &str = r###"
(element
   (STag
      (Name) @project
   )
   (content
      (element
         (STag
            (Name) @parent
         )
         (content
            (element
               (STag
                  (Name) @key
               )
               (content) @value
            )

         )
      )
   )
   (#eq? @project "project")
   (#eq? @parent "parent")
)
"###;

const TREE_SITTER_QUERY_DEPENDENCIES: &str = r###"
(element
   (STag
      (Name)@name
   )
   (content
     (
         (element
            (STag
               (Name)@tag
            )
            (content)@value
         )
         (CharData)
     )+
   )
   (#eq? @name "dependency")
   (#match? @tag "^artifactId$|^groupId$|^version$")
)
"###;

pub struct JvmPom {
    query_variables: tree_sitter::Query,
    query_dependencies: tree_sitter::Query,
}

impl JvmPom {
    pub fn new() -> Self {
        let tree_sitter_language_xml = get_tree_sitter_language(&Language::Xml);
        JvmPom {
            query_variables: tree_sitter::Query::new(
                &tree_sitter_language_xml,
                TREE_SITTER_QUERY_VARIABLES,
            )
            .expect("got query variables"),
            query_dependencies: tree_sitter::Query::new(
                &tree_sitter_language_xml,
                TREE_SITTER_QUERY_DEPENDENCIES,
            )
            .expect("got query dependencies"),
        }
    }

    fn get_variables(
        &self,
        tree: &tree_sitter::Tree,
        file_content: &str,
    ) -> HashMap<String, String> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut variables = HashMap::new();
        let matches = cursor.matches(
            &self.query_variables,
            tree.root_node(),
            file_content.as_bytes(),
        );
        for m in matches {
            let key_node = m.captures[2].node;
            let value_node = m.captures[3].node;
            let key = file_content[key_node.start_byte()..key_node.end_byte()].to_string();
            let value = file_content[value_node.start_byte()..value_node.end_byte()].to_string();
            variables.insert(key, value);
        }
        // println!("variables={:?}", variables);
        return variables;
    }
}

impl Analyzer for JvmPom {
    fn get_ecosystem(&self) -> Ecosystem {
        return Ecosystem::Jvm;
    }

    fn get_file_extension(&self) -> String {
        return "xml".to_string();
    }

    fn parse_file(&self, path: &str) -> anyhow::Result<Vec<Dependency>> {
        let variable_regex = Regex::new(r"^\$\{[a-zA-Z0-9]+\.(.+)\}$").unwrap();
        let file_content = fs::read_to_string(&path)?;
        let dependencies: Vec<Dependency> = get_tree(file_content.as_str(), &Language::Xml)
            .map(|tree| {
                let variables = self.get_variables(&tree, &file_content);
                let mut cursor = tree_sitter::QueryCursor::new();
                let mut dependencies = vec![];
                let matches = cursor.matches(
                    &self.query_dependencies,
                    tree.root_node(),
                    file_content.as_bytes(),
                );
                for m in matches {
                    let mut group_id_opt = None;
                    let mut artifact_id_opt = None;
                    let mut version_opt = None;

                    if m.captures.len() == 1 {
                        continue;
                    }

                    for i in (1..m.captures.len()).step_by(2) {
                        let tag_node = m.captures[i].node;
                        let value_node = m.captures[i + 1].node;

                        let tag =
                            file_content[tag_node.start_byte()..tag_node.end_byte()].to_string();
                        let value = file_content[value_node.start_byte()..value_node.end_byte()]
                            .to_string();

                        if tag == "artifactId" {
                            artifact_id_opt = Some(value.clone());
                        }
                        if tag == "groupId" {
                            group_id_opt = Some(value.clone());
                        }
                        if tag == "version" {
                            version_opt = Some(value.clone());
                        }
                    }

                    if let (Some(group_id), Some(artifact_id), Some(mut version)) =
                        (group_id_opt, artifact_id_opt, version_opt)
                    {
                        let captures_opt = variable_regex.captures(&version);
                        if let (Some(caps)) = captures_opt {
                            let variable_value = caps
                                .get(1)
                                .map_or("".to_string(), |m| m.as_str().to_string());
                            // println!("var value={}", variable_value);
                            if variables.contains_key(&variable_value) {
                                version = variables.get(&variable_value).unwrap().clone();
                            }
                        }
                        dependencies.push(Dependency {
                            name: group_id.clone(),
                            version: version.to_string(),
                            purl: "purl".to_string(),
                        })
                    }
                }
                dependencies
            })
            .unwrap_or(vec![]);
        Ok(dependencies)
    }
}
