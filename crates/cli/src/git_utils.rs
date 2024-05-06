use crate::constants::{GITLAB_ENVIRONMENT_VARIABLE_COMMIT_BRANCH, GIT_HEAD};
use git2::Repository;
use std::env;

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
