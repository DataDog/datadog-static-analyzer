use std::path::{Path, PathBuf};
use std::process::Command;

fn run<F>(name: &str, mut configure: F)
where
    F: FnMut(&mut Command) -> &mut Command,
{
    let mut command = Command::new(name);
    println!("Running {command:?}");
    let configured = configure(&mut command);
    assert!(
        configured.status().is_ok(),
        "failed to execute {configured:?}"
    );
}

fn main() {
    struct TreeSitterProject {
        name: String,       // the directory where we clone the project
        repository: String, // the repository to clone
        build_dir: PathBuf, // the directory we use to build the tree-sitter project
        files: Vec<String>,
        cpp: bool,
    }

    fn compile_project(tree_sitter_project: &TreeSitterProject) {
        let dir = &tree_sitter_project.build_dir;
        let files: Vec<PathBuf> = tree_sitter_project
            .files
            .iter()
            .map(|x| dir.join(x))
            .collect();
        let cpp = tree_sitter_project.cpp;
        let mut cc_build = cc::Build::new();
        let initial_build = cc_build.include(dir).files(files).warnings(false).cpp(cpp);

        let build_with_flag = if tree_sitter_project.cpp {
            initial_build.flag("-X c")
        } else {
            initial_build
        };

        build_with_flag.compile(tree_sitter_project.name.as_str());
    }

    let tree_sitter_projects: Vec<TreeSitterProject> = vec![
        TreeSitterProject {
            name: "tree-sitter-c-sharp".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-c-sharp.git".to_string(),
            build_dir: ["tree-sitter-c-sharp", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-dockerfile".to_string(),
            repository: "https://github.com/camdencheek/tree-sitter-dockerfile.git".to_string(),
            build_dir: ["tree-sitter-dockerfile", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-go".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-go.git".to_string(),
            build_dir: ["tree-sitter-go", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-hcl".to_string(),
            repository: "https://github.com/MichaHoffmann/tree-sitter-hcl.git".to_string(),
            build_dir: ["tree-sitter-hcl", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-kotlin".to_string(),
            repository: "https://github.com/fwcd/tree-sitter-kotlin.git".to_string(),
            build_dir: ["tree-sitter-kotlin", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-java".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-java.git".to_string(),
            build_dir: ["tree-sitter-java", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-javascript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-javascript.git".to_string(),
            build_dir: ["tree-sitter-javascript", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-json".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-json.git".to_string(),
            build_dir: ["tree-sitter-json", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-python".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-python.git".to_string(),
            build_dir: ["tree-sitter-python", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-rust".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-rust.git".to_string(),
            build_dir: ["tree-sitter-rust", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-typescript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-typescript.git".to_string(),
            build_dir: ["tree-sitter-typescript", "tsx", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-yaml".to_string(),
            repository: "https://github.com/juli1/tree-sitter-yaml.git".to_string(),
            build_dir: ["tree-sitter-yaml", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.cc".to_string()],
            cpp: true,
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
        compile_project(&tree_sitter_project);
    }
}
