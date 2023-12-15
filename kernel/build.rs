use deno_core::extension;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

// Create a snapshot of the JS runtime during compilation
// and persist it to the package's OUT_DIR as DENO_SNAPSHOT.bin.
// The contents of DENO_SNAPSHOT.bin will be directly included in the compiled executable later,
// and will be accessible as a static byte slice during execution to initialize the JS runtime.
//
// Refer to https://doc.rust-lang.org/cargo/reference/environment-variables.html for info on
// OUT_DIR and CARGO_MANIFEST_DIR
fn create_deno_snapshot() {
    extension!(deno_extension, js = ["src/analysis/js/stella.js",]);
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR environment variable not found"));
    let snapshot_path = out_dir.join("DENO_SNAPSHOT.bin");

    let _snapshot = deno_core::snapshot_util::create_snapshot(
        deno_core::snapshot_util::CreateSnapshotOptions {
            cargo_manifest_dir: env!("CARGO_MANIFEST_DIR"),
            snapshot_path,
            startup_snapshot: None,
            skip_op_registration: false,
            extensions: vec![deno_extension::init_ops_and_esm()],
            compression_cb: None,
            with_runtime_cb: None,
        },
    );
}

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
    create_deno_snapshot();
    struct TreeSitterProject {
        name: String,             // the directory where we clone the project
        compilation_unit: String, // name of the unit we compile
        repository: String,       // the repository to clone
        build_dir: PathBuf,       // the directory we use to build the tree-sitter project
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
            build_dir: ["tree-sitter-c-sharp", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-dockerfile".to_string(),
            compilation_unit: "tree-sitter-dockerfile".to_string(),
            repository: "https://github.com/camdencheek/tree-sitter-dockerfile.git".to_string(),
            build_dir: ["tree-sitter-dockerfile", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-go".to_string(),
            compilation_unit: "tree-sitter-go".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-go.git".to_string(),
            build_dir: ["tree-sitter-go", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-hcl".to_string(),
            compilation_unit: "tree-sitter-hcl".to_string(),
            repository: "https://github.com/MichaHoffmann/tree-sitter-hcl.git".to_string(),
            build_dir: ["tree-sitter-hcl", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-kotlin".to_string(),
            compilation_unit: "tree-sitter-kotlin".to_string(),
            repository: "https://github.com/fwcd/tree-sitter-kotlin.git".to_string(),
            build_dir: ["tree-sitter-kotlin", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-java".to_string(),
            compilation_unit: "tree-sitter-java".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-java.git".to_string(),
            build_dir: ["tree-sitter-java", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-javascript".to_string(),
            compilation_unit: "tree-sitter-javascript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-javascript.git".to_string(),
            build_dir: ["tree-sitter-javascript", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-json".to_string(),
            compilation_unit: "tree-sitter-json".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-json.git".to_string(),
            build_dir: ["tree-sitter-json", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-python".to_string(),
            compilation_unit: "tree-sitter-python".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-python.git".to_string(),
            build_dir: ["tree-sitter-python", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-rust".to_string(),
            compilation_unit: "tree-sitter-rust".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-rust.git".to_string(),
            build_dir: ["tree-sitter-rust", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-typescript".to_string(),
            compilation_unit: "tree-sitter-typescript".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-typescript.git".to_string(),
            build_dir: ["tree-sitter-typescript", "tsx", "src"].iter().collect(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-yaml".to_string(),
            compilation_unit: "tree-sitter-yaml-parser".to_string(),
            repository: "https://github.com/ikatyang/tree-sitter-yaml.git".to_string(),
            build_dir: ["tree-sitter-yaml", "src"].iter().collect(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-yaml".to_string(),
            compilation_unit: "tree-sitter-yaml-scanner".to_string(),
            repository: "https://github.com/ikatyang/tree-sitter-yaml.git".to_string(),
            build_dir: ["tree-sitter-yaml", "src"].iter().collect(),
            files: vec!["scanner.cc".to_string()],
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
