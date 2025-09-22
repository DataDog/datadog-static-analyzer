use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

/// Executes a [`Command`], returning true if the command finished with exit status 0, otherwise false
fn run<F>(name: &str, mut configure: F) -> bool
where
    F: FnMut(&mut Command) -> &mut Command,
{
    let mut command = Command::new(name);
    let configured = configure(&mut command);
    println!("Running {configured:?}");
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
            name: "tree-sitter-elixir".to_string(),
            compilation_unit: "tree-sitter-elixir".to_string(),
            repository: "https://github.com/elixir-lang/tree-sitter-elixir.git".to_string(),
            commit_hash: "02a6f7fd4be28dd94ee4dd2ca19cb777053ea74e".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
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
            repository: "https://github.com/tree-sitter-grammars/tree-sitter-kotlin.git"
                .to_string(),
            commit_hash: "77dd60ea0a9003ce062c9728a513ffe1aaff8c82".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-java".to_string(),
            compilation_unit: "tree-sitter-java".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-java.git".to_string(),
            commit_hash: "e10607b45ff745f5f876bfa3e94fbcc6b44bdc11".to_string(),
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
        // fork of tree-sitter-swift based on
        // https://github.com/alex-pinkus/tree-sitter-swift/commit/78d84ef82c387fceeb6094038da28717ea052e39
        // with the generated parser.c and scanner.c
        TreeSitterProject {
            name: "tree-sitter-swift".to_string(),
            compilation_unit: "tree-sitter-swift".to_string(),
            repository: "https://github.com/muh-nee/tree-sitter-swift.git".to_string(),
            build_dir: "src".into(),
            commit_hash: "434a6e90a6ce04ee8cc800902fa6357d0723c833".to_string(),
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
        TreeSitterProject {
            name: "tree-sitter-php".to_string(),
            compilation_unit: "tree-sitter-php".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-php.git".to_string(),
            build_dir: "php/src".into(),
            commit_hash: "575a0801f430c8672db70b73493c033a9dcfc328".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-markdown".to_string(),
            compilation_unit: "tree-sitter-markdown".to_string(),
            repository: "https://github.com/tree-sitter-grammars/tree-sitter-markdown".to_string(),
            build_dir: "tree-sitter-markdown/src".into(),
            commit_hash: "7fe453beacecf02c86f7736439f238f5bb8b5c9b".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-apex".to_string(),
            compilation_unit: "tree-sitter-apex".to_string(),
            repository: "https://github.com/aheber/tree-sitter-sfapex".to_string(),
            build_dir: "apex/src".into(),
            commit_hash: "3597575a429766dd7ecce9f5bb97f6fec4419d5d".to_string(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-r".to_string(),
            compilation_unit: "tree-sitter-r".to_string(),
            repository: "https://github.com/r-lib/tree-sitter-r".to_string(),
            build_dir: "src".into(),
            commit_hash: "369d20ff5d9fced274d3065b792951b23981b63d".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-sql".to_string(),
            compilation_unit: "tree-sitter-sql".to_string(),
            repository: "https://github.com/DerekStride/tree-sitter-sql".to_string(),
            build_dir: "src".into(),
            commit_hash: "c67ecbd37d8d12f22e4cc7138afd14bc20253e10".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
    ];

    // For each project:
    // 1. Check if the source is already present in the folder. It not, fetch it at the specified hash via git
    // 2. Build the project
    let base_dir = env::current_dir().unwrap();
    for proj in &tree_sitter_projects {
        let project_dir: PathBuf = [
            Path::new(".vendor"),
            Path::new(&format!("{}@{}", proj.name, proj.commit_hash)),
        ]
        .iter()
        .collect();

        if !project_dir.exists() {
            fs::create_dir_all(&project_dir).expect("Failed to create project directory");

            env::set_current_dir(&project_dir).unwrap();
            assert!(run("git", |cmd| { cmd.args(["init", "-q"]) }));
            assert!(run("git", |cmd| {
                cmd.args(["remote", "add", "origin", &proj.repository])
            }));
            assert!({
                let mut ok = false;
                let mut retry_time = std::time::Duration::from_secs(1);
                for _ in 0..5 {
                    ok = run("git", |cmd| {
                        cmd.args(["fetch", "-q", "--depth", "1", "origin", &proj.commit_hash])
                    });
                    if ok {
                        break;
                    }
                    std::thread::sleep(retry_time);
                    retry_time *= 2; // Exponential backoff
                }
                ok
            });
            assert!(run("git", |cmd| {
                cmd.args(["checkout", "-q", "FETCH_HEAD"])
            }));

            fs::remove_dir_all(".git").expect("Failed to remove .git directory");
            env::set_current_dir(&base_dir).unwrap();
        }
        env::set_current_dir(&project_dir).unwrap();
        compile_project(proj);
        env::set_current_dir(&base_dir).unwrap();
    }
}
