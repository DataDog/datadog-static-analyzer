use crate::model::common::Language;

pub const PROTOBUF_HEADER: &str = "Generated by the protocol buffer compiler.  DO NOT EDIT!";
pub const THRIFT_HEADER: &str = "Autogenerated by Thrift Compiler";

/// Returns if a file is generated or not based on a few heuristics.
/// Some heuristics are based on these sources
///  - https://github.com/github-linguist/linguist/blob/master/lib/linguist/generated.rb
pub fn is_generated_file(content: &str, language: &Language) -> bool {
    match language {
        Language::Go => {
            if content.contains("Code generated by MockGen") {
                return true;
            }
            if content.contains("Code generated by") {
                return true;
            }
            if content.contains(PROTOBUF_HEADER) {
                return true;
            }
            if content.contains(THRIFT_HEADER) {
                return true;
            }
            false
        }
        Language::Java => {
            if content.contains("generated by the protocol buffer compiler") {
                return true;
            }
            if content.contains(PROTOBUF_HEADER) {
                return true;
            }
            if content.contains(THRIFT_HEADER) {
                return true;
            }
            false
        }
        Language::JavaScript => {
            if content.contains("Generated by PEG.js") {
                return true;
            }
            if content.contains("GENERATED CODE -- DO NOT EDIT!") {
                return true;
            }
            if content.contains(THRIFT_HEADER) {
                return true;
            }
            return false;
        }
        Language::Python => {
            if content.contains("Generated protocol buffer code") {
                return true;
            }
            if content.contains("Code generated by") {
                return true;
            }
            if content.contains(PROTOBUF_HEADER) {
                return true;
            }
            if content.contains(THRIFT_HEADER) {
                return true;
            }
            false
        }
        Language::Ruby => {
            if content.contains(PROTOBUF_HEADER) {
                return true;
            }
            if content.contains(THRIFT_HEADER) {
                return true;
            }
            false
        }
        Language::TypeScript => {
            if content.contains("Generated by PEG.js") {
                return true;
            }
            if content.contains("GENERATED CODE -- DO NOT EDIT!") {
                return true;
            }
            if content.contains(THRIFT_HEADER) {
                return true;
            }
            return false;
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::generated_content::is_generated_file;
    use crate::model::common::Language;

    #[test]
    fn test_is_generated_file_java() {
        assert!(!is_generated_file(&"class Foobar", &Language::Java));
        assert!(is_generated_file(
            &"// generated by the protocol buffer compiler\n class Foobar{}",
            &Language::Java
        ));
    }

    #[test]
    fn test_is_generated_file_go() {
        assert!(!is_generated_file(&"fn func(){}", &Language::Go));
        assert!(is_generated_file(
            &"// Code generated by MockGen\nfn func(){}",
            &Language::Go
        ));
    }

    #[test]
    fn test_is_generated_file_python() {
        assert!(!is_generated_file(
            &"def foo():\n  pass\n",
            &Language::Python
        ));
        assert!(is_generated_file(
            &"# Code generated by some tool\ndef foo():\n  pass\n",
            &Language::Go
        ));
    }

    #[test]
    fn test_is_generated_file_javascript() {
        assert!(!is_generated_file(
            &"function smtg(){}",
            &Language::JavaScript
        ));
        assert!(is_generated_file(
            &"// GENERATED CODE -- DO NOT EDIT!\nfunction smtg(){}",
            &Language::JavaScript
        ));
    }

    #[test]
    fn test_is_generated_file_typescript() {
        assert!(!is_generated_file(
            &"function smtg(){}",
            &Language::TypeScript
        ));
        assert!(is_generated_file(
            &"// GENERATED CODE -- DO NOT EDIT!\nfunction smtg(){}",
            &Language::TypeScript
        ));
    }
}