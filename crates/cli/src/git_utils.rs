use anyhow::anyhow;
use git2::{DiffLineType, DiffOptions, Repository};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use crate::constants::{GITLAB_ENVIRONMENT_VARIABLE_COMMIT_BRANCH, GIT_HEAD};

/// The string to reference the head on the remote (hopefully pointing to the default branch)
const REMOTE_HEAD_REF: &str = "refs/remotes/origin/HEAD";
const ORIGIN_PREFIX: &str = "origin/";

/// Try to get the branch running. We first try to get the branch from the repository. When
/// it fails, we attempt to get the branch from the CI provider when the analyzer
/// runs in a CI provider.
///
/// Some CI providers (like Gitlab) runs their CI on a detached HEAD (see
/// [this thread for example](https://forum.gitlab.com/t/why-i-cant-get-the-branch-name/72462).
///
/// When we do not find the branch, we attempt to find it from the CI provider using variables.
pub fn get_branch(repository: &Repository, use_debug: bool) -> Option<String> {
    // First, let's try to get it from the repository.
    let head_try = repository.head();
    if let Ok(head) = head_try {
        let branch_from_shorthand = head.shorthand();

        if let Some(branch) = branch_from_shorthand {
            if branch == GIT_HEAD && use_debug {
                eprintln!("branch is HEAD, not using it for diff-aware");
            }

            if branch != GIT_HEAD {
                if use_debug {
                    eprintln!("Getting branch {} from Git repo", branch)
                }

                return Some(branch.to_string());
            }
        }
    }

    // Let's try to get it from Gitlab.
    let branch_from_gitlab_pipeline_try = env::var(GITLAB_ENVIRONMENT_VARIABLE_COMMIT_BRANCH);
    if let Ok(branch_from_gitlab_pipeline) = branch_from_gitlab_pipeline_try {
        if use_debug {
            eprintln!(
                "getting branch {} from Gitlab pipelines",
                branch_from_gitlab_pipeline
            );
        }
        return Some(branch_from_gitlab_pipeline);
    }

    None
}

/// Get the default branch of [repository]. To do so, we check the head ref on remote, which
/// is hopefully on the default branch.
pub fn get_default_branch(repository: &Repository) -> anyhow::Result<String> {
    let head_ref = repository.find_reference(REMOTE_HEAD_REF)?;
    let resolved_ref = head_ref.resolve()?;
    let branch_name_opt = resolved_ref.shorthand();

    if let Some(branch_name) = branch_name_opt {
        if branch_name.starts_with(ORIGIN_PREFIX) {
            let bn = &branch_name[ORIGIN_PREFIX.len()..branch_name.len()];
            return Ok(bn.to_string());
        }
    }
    Err(anyhow!("cannot find the default branch"))
}

/// Get the list of changed files for the repository between the latest commit the repository
/// is at and the default branch pointed by [default_branch].
/// The [repository] object is the repository built by git2.
/// It returns a map where the key is the path of the file and the value is the list of lines
/// that have been added (understand: added/updated).
pub fn get_changed_files(
    repository: &Repository,
    branch_name: &str,
) -> anyhow::Result<HashMap<PathBuf, Vec<u32>>> {
    // final result
    let mut res: HashMap<PathBuf, Vec<u32>> = HashMap::new();

    // the latest commit on the local head
    let head_commit = repository.head()?.peel_to_commit()?;

    // the commit of the default branch.
    let branch_commit = repository
        .find_branch(branch_name, git2::BranchType::Local)?
        .get()
        .peel_to_commit()?;

    // diff between local and default branch
    let diff = repository.diff_tree_to_tree(
        Some(&branch_commit.tree()?),
        Some(&head_commit.tree()?),
        Some(&mut DiffOptions::new()),
    )?;

    // for each element, we find the lines that have been added.
    diff.foreach(
        &mut |_, _| true,
        None,
        None,
        Some(&mut |delta, _diffhunk, diff_line| {
            let origin = diff_line.origin_value();

            // if this is not an add, we keep going. Note that when a line is updated, it's
            // marked as both an remove and an add.
            if origin != DiffLineType::Addition && origin != DiffLineType::AddEOFNL {
                return true;
            }

            if let (Some(path), Some(line)) = (delta.new_file().path(), diff_line.new_lineno()) {
                let pb = PathBuf::from(path);
                res.entry(pb)
                    .and_modify(|e| e.push(line))
                    .or_insert_with(|| vec![line]);
            }

            true
        }),
    )?;

    Ok(res)
}
