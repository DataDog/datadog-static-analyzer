
use crate::model::language::Language;

pub fn get_tree_sitter_language(language: &Language) -> tree_sitter::Language {
    extern "C" {
        fn tree_sitter_c_sharp() -> tree_sitter::Language;
        fn tree_sitter_dart() -> tree_sitter::Language;
        fn tree_sitter_dockerfile() -> tree_sitter::Language;
        fn tree_sitter_elixir() -> tree_sitter::Language;
        fn tree_sitter_go() -> tree_sitter::Language;
        fn tree_sitter_java() -> tree_sitter::Language;
        fn tree_sitter_javascript() -> tree_sitter::Language;
        fn tree_sitter_json() -> tree_sitter::Language;
        fn tree_sitter_kotlin() -> tree_sitter::Language;
        fn tree_sitter_python() -> tree_sitter::Language;
        fn tree_sitter_ruby() -> tree_sitter::Language;
        fn tree_sitter_rust() -> tree_sitter::Language;
        fn tree_sitter_swift() -> tree_sitter::Language;
        fn tree_sitter_tsx() -> tree_sitter::Language;
        fn tree_sitter_hcl() -> tree_sitter::Language;
        fn tree_sitter_yaml() -> tree_sitter::Language;
        fn tree_sitter_starlark() -> tree_sitter::Language;
        fn tree_sitter_bash() -> tree_sitter::Language;
        fn tree_sitter_php() -> tree_sitter::Language;
        fn tree_sitter_markdown() -> tree_sitter::Language;
        fn tree_sitter_apex() -> tree_sitter::Language;
        fn tree_sitter_r() -> tree_sitter::Language;
        fn tree_sitter_sql() -> tree_sitter::Language;
    }

    match language {
        Language::Csharp => unsafe { tree_sitter_c_sharp() },
        Language::Dart => unsafe { tree_sitter_dart() },
        Language::Dockerfile => unsafe { tree_sitter_dockerfile() },
        Language::Go => unsafe { tree_sitter_go() },
        Language::Elixir => unsafe { tree_sitter_elixir() },
        Language::Java => unsafe { tree_sitter_java() },
        Language::JavaScript => unsafe { tree_sitter_javascript() },
        Language::Kotlin => unsafe { tree_sitter_kotlin() },
        Language::Json => unsafe { tree_sitter_json() },
        Language::Python => unsafe { tree_sitter_python() },
        Language::Ruby => unsafe { tree_sitter_ruby() },
        Language::Rust => unsafe { tree_sitter_rust() },
        Language::Swift => unsafe { tree_sitter_swift() },
        Language::Terraform => unsafe { tree_sitter_hcl() },
        Language::TypeScript => unsafe { tree_sitter_tsx() },
        Language::Yaml => unsafe { tree_sitter_yaml() },
        Language::Starlark => unsafe { tree_sitter_starlark() },
        Language::Bash => unsafe { tree_sitter_bash() },
        Language::PHP => unsafe { tree_sitter_php() },
        Language::Markdown => unsafe { tree_sitter_markdown() },
        Language::Apex => unsafe { tree_sitter_apex() },
        Language::R => unsafe { tree_sitter_r() },
        Language::SQL => unsafe { tree_sitter_sql() },
    }
}

// get the tree-sitter tree
pub fn get_tree(code: &str, language: &Language) -> Option<tree_sitter::Tree> {
    let mut tree_sitter_parser = tree_sitter::Parser::new();
    let tree_sitter_language = get_tree_sitter_language(language);
    tree_sitter_parser
        .set_language(&tree_sitter_language)
        .ok()?;
    tree_sitter_parser.parse(code, None)
}




#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;
    use crate::tree_sitter::tree_sitter::get_tree;

    #[test]
    fn test_python_get_tree() {
        let source_code = r#"
arr = ["foo", "bar"];

def func():
   pass;"#;
        let t = get_tree(source_code, &Language::Python);
        assert!(t.is_some());
        assert_eq!("module", t.unwrap().root_node().kind());
    }


    #[test]
    fn test_csharp_get_tree() {
        let source_code = r#"
namespace HelloWorld
{
    class Hello {
        static void Main(string[] args)
        {
            System.Console.WriteLine("Hello World!");
        }
    }
}
"#;
        let t = get_tree(source_code, &Language::Csharp);
        assert!(t.is_some());
        assert_eq!("compilation_unit", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_dockerfile_get_tree() {
        let source_code = r#"
RUN /blabla
"#;
        let t = get_tree(source_code, &Language::Dockerfile);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_go_test_tree() {
        let source_code = r#"
package main
import "fmt"
func main() {
    fmt.Println("hello world")
}
"#;
        let t = get_tree(source_code, &Language::Go);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_java_get_tree() {
        let source_code = r#"
class Foo {
}
"#;
        let t = get_tree(source_code, &Language::Java);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_javascript_get_tree() {
        let source_code = r#"
function foo() {console.log("bar");}"#;
        let t = get_tree(source_code, &Language::JavaScript);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_json_get_tree() {
        let source_code = r#"
{}"#;
        let t = get_tree(source_code, &Language::Json);
        assert!(t.is_some());
        assert_eq!("document", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_dart_get_tree() {
        let source_code = r#"void main() {
  print('Hello, Dart!');
}
"#;
        let t = get_tree(source_code, &Language::Dart);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_ruby_get_tree() {
        let source_code = r#"def greeting
  puts "Hello Ruby!"
  return
end

greeting()
"#;
        let t = get_tree(source_code, &Language::Ruby);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_rust_get_tree() {
        let source_code = r#"
fn foo(bar: String) -> String {
   return "foobar".to_string();
}
"#;
        let t = get_tree(source_code, &Language::Rust);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_kotlin_get_tree() {
        let source_code = r#"
fun main() {
    println("What's your name?")
    val name = readln()
    println("Hello, $name!")
}
"#;
        let t = get_tree(source_code, &Language::Kotlin);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_swift_get_tree() {
        let source_code = r#"
// HelloWorld.swift
import Foundation
print("Hello, World!")

"#;
        let t = get_tree(source_code, &Language::Swift);
        assert!(t.is_some());
        assert_eq!("source_file", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_typescript_get_tree() {
        let source_code = r#"
let myAdd = function (x: number, y: number): number {
  return x + y;
};
"#;
        let t = get_tree(source_code, &Language::TypeScript);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_yaml_get_tree() {
        let source_code = r#"
rulesets:
  - my-ruleset
"#;
        let t = get_tree(source_code, &Language::Yaml);
        assert!(t.is_some());
        assert_eq!("stream", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_starlark_get_tree() {
        let source_code = r#"
load("@io_bazel_rules_docker//container:container.bzl", "container_image")
container_image(
    name = "base",
    base = "@io_bazel_rules_docker//images/ubuntu-1604:latest",
)
"#;
        let t = get_tree(source_code, &Language::Starlark);
        assert!(t.is_some());
        assert_eq!("module", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_bash_get_tree() {
        let source_code = r#"
echo "Hello, World!"
"#;
        let t = get_tree(source_code, &Language::Bash);
        assert!(t.is_some());
        assert_eq!("program", t.unwrap().root_node().kind());
    }

    #[test]
    fn test_php_get_tree() {
        let source_code = r#"
<?php
echo "Hello, World!";
?>
"#;
        let t = get_tree(source_code, &Language::PHP);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }

    #[test]
    fn test_markdown_get_tree() {
        let source_code = r#"
# Hello, World!
This is some text
"#;
        let t = get_tree(source_code, &Language::Markdown);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("document", t.root_node().kind());
    }

    #[test]
    fn test_apex_get_tree() {
        let source_code = r#"
public class HelloWorld {
    public static void main() {
        System.out.println('Hello, World');
    }
}"#;
        let t = get_tree(source_code, &Language::Apex);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("parser_output", t.root_node().kind());
    }

    #[test]
    fn test_r_get_tree() {
        let source_code = r#"
x <- 1
print("Hello, World!")
"#;
        let t = get_tree(source_code, &Language::R);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }

    #[test]
    fn test_elixir_get_tree() {
        let source_code = r#"
defmodule Sum do
  def add(a, b) do
    a + b
  end
end
"#;
        let t = get_tree(source_code, &Language::Elixir);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("source", t.root_node().kind());
    }

    #[test]
    fn test_sql_get_tree() {
        let source_code = r#"
SELECT * FROM table WHERE column = 'value';
"#;
        let t = get_tree(source_code, &Language::SQL);
        assert!(t.is_some());
        let t = t.unwrap();
        assert!(!t.root_node().has_error());
        assert_eq!("program", t.root_node().kind());
    }
    
}
