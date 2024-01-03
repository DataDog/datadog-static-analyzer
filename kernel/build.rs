use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn run<F>(name: &str, mut configure: F) -> ExitStatus
where
    F: FnMut(&mut Command) -> &mut Command,
{
    let mut command = Command::new(name);
    println!("Running {command:?}");
    let configured = configure(&mut command);
    configured
        .status()
        .unwrap_or_else(|_| panic!("failed to execute {configured:?}"))
}

fn main() {
    struct TreeSitterProject {
        /// The directory where we clone the project
        name: String,
        /// The name of the unit we compile
        compilation_unit: String,
        /// The git repository to clone
        repository: String,
        /// The git commit hash that will be passed to `git checkout`
        commit_hash: String,
        /// The directory we use to build the tree-sitter project
        build_dir: PathBuf,
        /// The files to pass to the `cc::Build` instance
        files: Vec<String>,
        /// Whether compilation of this project requires C++ support or not
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
        cc::Build::new()
            .include(dir)
            .files(files)
            .warnings(false)
            .cpp(cpp)
            .compile(tree_sitter_project.compilation_unit.as_str());
    }

    let tree_sitter_projects: Vec<TreeSitterProject> = vec![
        TreeSitterProject {
            name: "tree-sitter-c-sharp".to_string(),
            compilation_unit: "tree-sitter-c-sharp".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-c-sharp.git".to_string(),
            commit_hash: "dd5e59721a5f8dae34604060833902b882023aaf".to_string(),
            build_dir: ["tree-sitter-c-sharp", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-dockerfile".to_string(),
            compilation_unit: "tree-sitter-dockerfile".to_string(),
            repository: "https://github.com/camdencheek/tree-sitter-dockerfile.git".to_string(),
            commit_hash: "33e22c33bcdbfc33d42806ee84cfd0b1248cc392".to_string(),
            build_dir: ["tree-sitter-dockerfile", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-go".to_string(),
            compilation_unit: "tree-sitter-go".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-go.git".to_string(),
            commit_hash: "ff86c7f1734873c8c4874ca4dd95603695686d7a".to_string(),
            build_dir: ["tree-sitter-go", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-hcl".to_string(),
            compilation_unit: "tree-sitter-hcl".to_string(),
            repository: "https://github.com/MichaHoffmann/tree-sitter-hcl.git".to_string(),
            commit_hash: "e135399cb31b95fac0760b094556d1d5ce84acf0".to_string(),
            build_dir: ["tree-sitter-hcl", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-kotlin".to_string(),
            compilation_unit: "tree-sitter-kotlin".to_string(),
            repository: "https://github.com/fwcd/tree-sitter-kotlin.git".to_string(),
            commit_hash: "0ef87892401bb01c84b40916e1f150197bc134b1".to_string(),
            build_dir: ["tree-sitter-kotlin", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-java".to_string(),
            compilation_unit: "tree-sitter-java".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-java.git".to_string(),
            commit_hash: "2b57cd9541f9fd3a89207d054ce8fbe72657c444".to_string(),
            build_dir: ["tree-sitter-java", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-javascript".to_string(),
            compilation_unit: "tree-sitter-javascript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-javascript.git".to_string(),
            commit_hash: "f1e5a09b8d02f8209a68249c93f0ad647b228e6e".to_string(),
            build_dir: ["tree-sitter-javascript", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-json".to_string(),
            compilation_unit: "tree-sitter-json".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-json.git".to_string(),
            commit_hash: "3fef30de8aee74600f25ec2e319b62a1a870d51e".to_string(),
            build_dir: ["tree-sitter-json", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-python".to_string(),
            compilation_unit: "tree-sitter-python".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-python.git".to_string(),
            commit_hash: "4bfdd9033a2225cc95032ce77066b7aeca9e2efc".to_string(),
            build_dir: ["tree-sitter-python", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-rust".to_string(),
            compilation_unit: "tree-sitter-rust".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-rust.git".to_string(),
            build_dir: ["tree-sitter-rust", "src"].iter().collect(),
            commit_hash: "79456e6080f50fc1ca7c21845794308fa5d35a51".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-typescript".to_string(),
            compilation_unit: "tree-sitter-typescript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-typescript.git".to_string(),
            build_dir: ["tree-sitter-typescript", "tsx", "src"].iter().collect(),
            commit_hash: "d847898fec3fe596798c9fda55cb8c05a799001a".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-yaml".to_string(),
            compilation_unit: "tree-sitter-yaml-parser".to_string(),
            repository: "https://github.com/ikatyang/tree-sitter-yaml.git".to_string(),
            build_dir: ["tree-sitter-yaml", "src"].iter().collect(),
            commit_hash: "0e36bed171768908f331ff7dff9d956bae016efb".to_string(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-yaml".to_string(),
            compilation_unit: "tree-sitter-yaml-scanner".to_string(),
            repository: "https://github.com/ikatyang/tree-sitter-yaml.git".to_string(),
            build_dir: ["tree-sitter-yaml", "src"].iter().collect(),
            commit_hash: "0e36bed171768908f331ff7dff9d956bae016efb".to_string(),
            files: vec!["scanner.cc".to_string()],
            cpp: true,
        },
        TreeSitterProject {
            name: "tree-sitter-c".to_string(),
            compilation_unit: "tree-sitter-c".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-c".to_string(),
            build_dir: ["tree-sitter-c", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
    ];

    // for each project
    //  1. Check if already clone. It not, clone it
    //  2. `checkout` the specified hash
    //  3. Build the project
    for tree_sitter_project in tree_sitter_projects {
        if !Path::new(tree_sitter_project.name.as_str()).exists() {
            run("git", |command| {
                command
                    .arg("clone")
                    .arg(tree_sitter_project.repository.as_str())
                    .arg(tree_sitter_project.name.as_str())
            });
        }
        let base_dir = env::current_dir().expect("should be able to get current dir");
        env::set_current_dir(Path::new(&tree_sitter_project.name))
            .expect("should be able to switch directories");
        let checkout_status = run("git", |command| {
            command.args(["checkout", &tree_sitter_project.commit_hash])
        });
        assert_eq!(
            checkout_status.code(),
            Some(0),
            "[{}] Unable to checkout `{}`",
            &tree_sitter_project.name,
            &tree_sitter_project.commit_hash,
        );
        env::set_current_dir(base_dir).expect("should be able to switch directories");
        compile_project(&tree_sitter_project);
    }
}
