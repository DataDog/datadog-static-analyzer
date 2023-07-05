use std::path::{Path, PathBuf};
use std::process::Command;

fn run<F>(name: &str, mut configure: F)
where
    F: FnMut(&mut Command) -> &mut Command,
{
    let mut command = Command::new(name);
    println!("Running {:?}", command);
    let configured = configure(&mut command);
    if configured.status().is_err() {
        panic!("failed to execute {:?}", configured);
    }
}

fn main() {
    struct TreeSitterProject {
        name: String,       // the directory where we clone the project
        repository: String, // the repository to clone
        build_dir: PathBuf, // the directory we use to build the tree-sitter project
    }

    let tree_sitter_projects: Vec<TreeSitterProject> = vec![
        TreeSitterProject {
            name: "tree-sitter-javascript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-javascript.git".to_string(),
            build_dir: ["tree-sitter-javascript", "src"].iter().collect(),
        },
        TreeSitterProject {
            name: "tree-sitter-python".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-python.git".to_string(),
            build_dir: ["tree-sitter-python", "src"].iter().collect(),
        },
        TreeSitterProject {
            name: "tree-sitter-rust".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-rust.git".to_string(),
            build_dir: ["tree-sitter-rust", "src"].iter().collect(),
        },
        TreeSitterProject {
            name: "tree-sitter-typescript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-typescript.git".to_string(),
            build_dir: ["tree-sitter-typescript", "tsx", "src"].iter().collect(),
        },
    ];

    // for each project
    //  1. Check if already clone. It not, clone it
    //  2. Build the project
    for tree_sitter_project in tree_sitter_projects {
        if !Path::new(tree_sitter_project.name.as_str()).exists() {
            run("git", |command| {
                command
                    .arg("clone")
                    .arg(tree_sitter_project.repository.as_str())
                    .arg(tree_sitter_project.name.as_str())
            });
        }
        let dir = &tree_sitter_project.build_dir;
        cc::Build::new()
            .include(dir)
            .file(dir.join("parser.c"))
            .file(dir.join("scanner.c"))
            .warnings(false)
            .compile(tree_sitter_project.name.as_str());
    }
}
