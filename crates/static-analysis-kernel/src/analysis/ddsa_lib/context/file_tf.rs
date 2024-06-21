// Unless explicitly stated otherwise all files in this repository are licensed under the Apache License, Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

use deno_core::v8::{self, HandleScope};

use crate::analysis::ddsa_lib::common::{Class, DDSAJsRuntimeError};
use crate::analysis::ddsa_lib::js;
use crate::analysis::ddsa_lib::v8_ds::MirroredVec;
use crate::analysis::tree_sitter::get_tree_sitter_language;
use crate::model::common::Language;

/// Terraform-specific file context
#[derive(Debug)]
pub struct FileContextTerraform {
    query: tree_sitter::Query,
    resources: MirroredVec<Resource, js::TerraformResource<Class>>,
}

/// Terraform resource representation, which consists of a type and a name.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Resource {
    pub r#type: String,
    pub name: String,
}

const TF_QUERY: &str = r#"
(block
  (identifier) @_resource
  (#eq? @_resource "resource")
  .
  (string_lit (template_literal) @type)
  .
  (string_lit (template_literal) @name)
)
"#;

impl FileContextTerraform {
    pub fn new(scope: &mut HandleScope) -> Result<Self, DDSAJsRuntimeError> {
        let resources = MirroredVec::new(js::TerraformResource::try_new(scope)?, scope);

        let ts_query =
            tree_sitter::Query::new(&get_tree_sitter_language(&Language::Terraform), TF_QUERY)
                .expect("query has valid syntax");

        Ok(Self {
            query: ts_query,
            resources,
        })
    }

    /// Queries the `tree_sitter::Tree` and updates the internal [`MirroredIndexMap`] with the query results.
    pub fn update_state(&mut self, scope: &mut HandleScope, tree: &tree_sitter::Tree, code: &str) {
        let mut query_cursor = tree_sitter::QueryCursor::new();
        let query_result = query_cursor.matches(&self.query, tree.root_node(), code.as_bytes());

        let resources = query_result
            .into_iter()
            .map(|query_match| {
                let mut resource_type = None;
                let mut resource_name = None;

                for capture in query_match.captures {
                    let start = capture.node.byte_range().start;
                    let end = capture.node.byte_range().end;
                    let capture_name = self.query.capture_names()[capture.index as usize];
                    match capture_name {
                        "type" => resource_type = Some(code.get(start..end).unwrap().to_string()),
                        "name" => resource_name = Some(code.get(start..end).unwrap().to_string()),
                        "_resource" => {}
                        _ => unreachable!(),
                    }
                }

                Resource {
                    r#type: resource_type.unwrap(),
                    name: resource_name.unwrap(),
                }
            })
            .collect::<Vec<_>>();

        self.resources.set_data(scope, resources);
    }

    /// Clears the internal [`MirroredVec`] of any resources.
    pub fn clear(&mut self, scope: &mut HandleScope) {
        self.resources.clear(scope);
    }

    /// Returns a reference to the [`v8::Global`] map backing the resources.
    pub(crate) fn resources_v8_array(&self) -> &v8::Global<v8::Array> {
        self.resources.v8_array()
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ddsa_lib::context::file_tf::FileContextTerraform;
    use crate::analysis::ddsa_lib::context::file_tf::Resource;
    use crate::analysis::ddsa_lib::test_utils::cfg_test_runtime;
    use crate::analysis::tree_sitter::get_tree;
    use crate::model::common::Language;

    #[test]
    fn test_get_file_context_tf() {
        let mut runtime = cfg_test_runtime();
        let scope = &mut runtime.handle_scope();
        let mut ctx_tf = FileContextTerraform::new(scope).unwrap();

        struct TestCase {
            code: &'static str,
            expected: Vec<Resource>,
        }

        let test = TestCase {
            code: r#"
                    resource "aws_instance" "app" {
                        ami           = "ami-1234567890"
                        instance_type = "t2.micro"
                    }

                    resource "aws_instance" "db" {
                        ami           = "ami-1234567890"
                        instance_type = "t2.micro"
                    }

                    resource "google_compute_instance" "web" {
                        project      = "my-project"
                        name         = "web"
                        machine_type = "n1-standard-1"
                    }
                "#,
            expected: vec![
                Resource {
                    r#type: "aws_instance".to_string(),
                    name: "app".to_string(),
                },
                Resource {
                    r#type: "aws_instance".to_string(),
                    name: "db".to_string(),
                },
                Resource {
                    r#type: "google_compute_instance".to_string(),
                    name: "web".to_string(),
                },
            ],
        };

        let tree = get_tree(test.code, &Language::Terraform).unwrap();
        ctx_tf.update_state(scope, &tree, test.code);
        assert_eq!(ctx_tf.resources.len(), test.expected.len());

        for (idx, expected) in test.expected.iter().enumerate() {
            let actual = ctx_tf.resources.get(idx).unwrap();
            assert_eq!(actual, expected, "Mismatch at index {idx}");
        }
    }
}
