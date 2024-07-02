use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Executes a [`Command`], returning true if the command finished with exit status 0, otherwise false
fn run<F>(name: &str, mut configure: F) -> bool
where
    F: FnMut(&mut Command) -> &mut Command,
{
    let mut command = Command::new(name);
    println!("Running {command:?}");
    let configured = configure(&mut command);
    configured
        .status()
        .unwrap_or_else(|_| panic!("failed to execute {configured:?}"))
        .success()
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
            commit_hash: "82fa8f05f41a33e9bc830f85d74a9548f0291738".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-dockerfile".to_string(),
            compilation_unit: "tree-sitter-dockerfile".to_string(),
            repository: "https://github.com/camdencheek/tree-sitter-dockerfile.git".to_string(),
            commit_hash: "33e22c33bcdbfc33d42806ee84cfd0b1248cc392".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-go".to_string(),
            compilation_unit: "tree-sitter-go".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-go.git".to_string(),
            commit_hash: "ff86c7f1734873c8c4874ca4dd95603695686d7a".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-hcl".to_string(),
            compilation_unit: "tree-sitter-hcl".to_string(),
            repository: "https://github.com/MichaHoffmann/tree-sitter-hcl.git".to_string(),
            commit_hash: "e135399cb31b95fac0760b094556d1d5ce84acf0".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-kotlin".to_string(),
            compilation_unit: "tree-sitter-kotlin".to_string(),
            repository: "https://github.com/fwcd/tree-sitter-kotlin.git".to_string(),
            commit_hash: "4e909d6cc9ac96b4eaecb3fb538eaca48e9e9ee9".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-java".to_string(),
            compilation_unit: "tree-sitter-java".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-java.git".to_string(),
            commit_hash: "5e62fbb519b608dfd856000fdc66536304c414de".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-javascript".to_string(),
            compilation_unit: "tree-sitter-javascript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-javascript.git".to_string(),
            commit_hash: "f1e5a09b8d02f8209a68249c93f0ad647b228e6e".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-json".to_string(),
            compilation_unit: "tree-sitter-json".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-json.git".to_string(),
            commit_hash: "3fef30de8aee74600f25ec2e319b62a1a870d51e".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-python".to_string(),
            compilation_unit: "tree-sitter-python".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-python.git".to_string(),
            commit_hash: "4bfdd9033a2225cc95032ce77066b7aeca9e2efc".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-rust".to_string(),
            compilation_unit: "tree-sitter-rust".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-rust.git".to_string(),
            build_dir: "src".into(),
            commit_hash: "79456e6080f50fc1ca7c21845794308fa5d35a51".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-typescript".to_string(),
            compilation_unit: "tree-sitter-typescript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-typescript.git".to_string(),
            build_dir: "tsx/src".into(),
            commit_hash: "d847898fec3fe596798c9fda55cb8c05a799001a".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-yaml".to_string(),
            compilation_unit: "tree-sitter-yaml-parser".to_string(),
            repository: "https://github.com/tree-sitter-grammars/tree-sitter-yaml.git".to_string(),
            build_dir: "src".into(),
            commit_hash: "ee093118211be521742b9866a8ed8ce6d87c7a94".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-ruby".to_string(),
            compilation_unit: "tree-sitter-ruby".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-ruby".to_string(),
            build_dir: "src".into(),
            commit_hash: "7a010836b74351855148818d5cb8170dc4df8e6a".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-swift".to_string(),
            compilation_unit: "tree-sitter-swift".to_string(),
            repository: "https://github.com/alex-pinkus/tree-sitter-swift.git".to_string(),
            build_dir: "src".into(),
            commit_hash: "b1b66955d420d5cf5ff268ae552f0d6e43ff66e1".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-starlark".to_string(),
            compilation_unit: "tree-sitter-starlark".to_string(),
            repository: "https://github.com/tree-sitter-grammars/tree-sitter-starlark.git"
                .to_string(),
            build_dir: "src".into(),
            commit_hash: "018d0e09d9d0f0dd6740a37682b8ee4512e8b2ac".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-bash".to_string(),
            compilation_unit: "tree-sitter-bash".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-bash.git".to_string(),
            build_dir: "src".into(),
            commit_hash: "2fbd860f802802ca76a6661ce025b3a3bca2d3ed".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
    ];

    // For each project:
    // 1. Check if the source is already present in the folder. It not, fetch it at the specified hash via git
    // 2. Build the project
    let base_dir = env::current_dir().unwrap();
    for proj in &tree_sitter_projects {
        let project_dir = format!(".vendor/{}@{}", &proj.name, &proj.commit_hash);
        if !Path::new(&project_dir).exists() {
            assert!(run("mkdir", |cmd| { cmd.args(["-p", &project_dir]) }));
            env::set_current_dir(&project_dir).unwrap();
            assert!(run("git", |cmd| { cmd.args(["init", "-q"]) }));
            assert!(run("git", |cmd| {
                cmd.args(["remote", "add", "origin", &proj.repository])
            }));
            assert!(run("git", |cmd| {
                cmd.args(["fetch", "-q", "--depth", "1", "origin", &proj.commit_hash])
            }));
            assert!(run("git", |cmd| {
                cmd.args(["checkout", "-q", "FETCH_HEAD"])
            }));
            assert!(run("rm", |cmd| { cmd.args(["-rf", ".git"]) }));
            env::set_current_dir(&base_dir).unwrap();
        }
        env::set_current_dir(&project_dir).unwrap();
        compile_project(proj);
        env::set_current_dir(&base_dir).unwrap();
    }
}
