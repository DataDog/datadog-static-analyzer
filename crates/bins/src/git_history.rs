// Git history secret scanning: scan every unique blob in the object database
// (pass 1), then attribute only the secret-bearing blobs back to their
// introducing/removal commits via a single `git log` pass (pass 2).

use cli::model::run_configuration::RunConfiguration;
use cli::sarif::sarif_utils::HistoricalSecretResult;
use common::analysis_options::AnalysisOptions;
use git2::{ObjectType, Oid, Repository, TreeWalkMode, TreeWalkResult};
use rayon::prelude::*;
use secrets::model::secret_result::SecretResult;
use secrets::model::secret_rule::SecretRule;
use secrets::scanner::{build_sds_scanner, find_secrets};
use secrets::secret_files::should_ignore_file_for_secret;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Placeholder path used when scanning a raw blob whose path is not yet known.
/// The secrets scanner only uses the filename for log/error messages, not for
/// matching, so any stable value works here.
const GIT_HISTORY_BLOB_PLACEHOLDER: &str = "<git-history-blob>";

/// An occurrence of a blob at a path in history, with its introducing commit
/// (where the blob was reachably added at that path) and, if applicable, the
/// commit that removed it from that path. Only occurrences with an
/// `introduced_at` are reported (a path known only via a deletion has its add on
/// an unreachable ancestor and must not produce a finding).
#[derive(Default)]
struct BlobOccurrence {
    introduced_at: Option<Oid>,
    removed_at: Option<Oid>,
}

/// Get the `BlobOccurrence` for a (blob, path) pair, creating an empty one if it
/// does not exist yet.
fn find_or_create_occurrence<'a>(
    registry: &'a mut HashMap<Oid, HashMap<String, BlobOccurrence>>,
    blob_oid: Oid,
    path: &str,
) -> &'a mut BlobOccurrence {
    registry
        .entry(blob_oid)
        .or_default()
        .entry(path.to_string())
        .or_default()
}

/// Collect all (blob_oid, path) pairs reachable from HEAD.
fn collect_head_blob_paths(repo: &Repository) -> HashSet<(Oid, String)> {
    let mut set = HashSet::new();
    let head = repo.head().ok().and_then(|r| r.peel_to_commit().ok());
    if let Some(commit) = head {
        if let Ok(tree) = commit.tree() {
            tree.walk(TreeWalkMode::PreOrder, |dir, entry| {
                if entry.kind() == Some(ObjectType::Blob) {
                    let path = if dir.is_empty() {
                        entry.name().unwrap_or("").to_string()
                    } else {
                        format!("{}{}", dir, entry.name().unwrap_or(""))
                    };
                    set.insert((entry.id(), path));
                }
                TreeWalkResult::Ok
            })
            .ok();
        }
    }
    set
}

/// Pass 1: scan every unique blob in the object database once for secrets.
///
/// The object database is content-addressed, so this naturally deduplicates blob
/// content for free: there is no commit or tree walk. Every unique blob is scanned
/// (including blobs whose content also exists at HEAD): a blob present at HEAD may
/// also live at a historical path, and HEAD exclusion is applied per-(blob, path) in
/// pass 2. Returns the blobs that contained at least one secret, keyed by blob OID.
fn scan_all_blobs_for_secrets(
    repo: &Repository,
    run_config: &RunConfiguration,
    secrets_rules: &[SecretRule],
    options: &AnalysisOptions,
) -> anyhow::Result<HashMap<Oid, Vec<SecretResult>>> {
    let sds_scanner =
        build_sds_scanner(secrets_rules, run_config.use_debug).map_err(|e| anyhow::anyhow!(e))?;
    // Enumerate every object OID (the callback only yields the OID; cheap, reads
    // the pack index without decompressing).
    let t_enum = std::time::Instant::now();
    let mut all_oids: Vec<Oid> = Vec::new();
    repo.odb()?.foreach(|oid| {
        all_oids.push(*oid);
        true
    })?;
    let total_objects = all_oids.len();
    eprintln!(
        "[git-history] pass1: enumerated {} objects in {:.1}s; scanning blobs on {} threads",
        total_objects,
        t_enum.elapsed().as_secs_f64(),
        run_config.num_cpus,
    );

    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    let objects_examined = AtomicU64::new(0);
    let blobs_scanned = AtomicU64::new(0);
    let secret_blobs = AtomicUsize::new(0);
    let t_scan = std::time::Instant::now();
    let source_directory = run_config.source_directory.clone();

    // git2 types are not `Send`, so each rayon worker opens (and reuses) its own
    // `Repository` handle via a thread-local. Rayon's global thread pool outlives any
    // single call to this function (e.g. across tests in the same process), so the cache
    // is keyed by source directory and re-opened whenever it doesn't match: otherwise a
    // worker thread that previously scanned a *different* repo would silently keep using
    // that stale handle, reading zero (or the wrong) blobs for the current repo.
    thread_local! {
        static TL_REPO: std::cell::RefCell<Option<(String, Repository)>> =
            const { std::cell::RefCell::new(None) };
    }

    let collected: Vec<(Oid, Vec<SecretResult>)> = all_oids
        .par_iter()
        .filter_map(|&oid| {
            let examined = objects_examined.fetch_add(1, Ordering::Relaxed) + 1;
            if examined.is_multiple_of(1_000_000) {
                let scanned = blobs_scanned.load(Ordering::Relaxed);
                eprintln!(
                    "[git-history] pass1: examined {}/{} objects, scanned {} blobs ({:.0}/s), {} with secrets",
                    examined,
                    total_objects,
                    scanned,
                    scanned as f64 / t_scan.elapsed().as_secs_f64().max(0.001),
                    secret_blobs.load(Ordering::Relaxed),
                );
            }

            // Read the blob content under a SHORT-LIVED borrow of the thread-local
            // repo, then release the borrow before scanning. `find_secrets` re-enters
            // the global rayon pool internally; if we held the `RefCell` borrow across
            // it, a stolen sibling task on the same worker thread would re-enter this
            // closure and panic with `already borrowed`. Copying the bytes out keeps
            // the borrow scope free of any rayon re-entry.
            let content: Option<String> = TL_REPO.with(|cell| {
                let mut slot = cell.borrow_mut();
                if slot.as_ref().is_none_or(|(dir, _)| dir != &source_directory) {
                    *slot = Repository::open(&source_directory)
                        .ok()
                        .map(|repo| (source_directory.clone(), repo));
                }
                let (_, repo) = slot.as_ref()?;
                let odb = repo.odb().ok()?;

                let obj = odb.read(oid).ok()?;
                // Copy the blob's text out so the borrow can be released before scanning.
                // Decode lossily to mirror the HEAD scan (read_file): a blob with invalid
                // UTF-8 bytes must still be scanned for secrets, not silently dropped.
                Some(String::from_utf8_lossy(obj.data()).into_owned())
            });
            let content = content?;

            let scanned = blobs_scanned.fetch_add(1, Ordering::Relaxed) + 1;
            if scanned.is_multiple_of(250_000) {
                eprintln!(
                    "[git-history] pass1: scanned {} blobs ({:.0}/s), {} with secrets",
                    scanned,
                    scanned as f64 / t_scan.elapsed().as_secs_f64().max(0.001),
                    secret_blobs.load(Ordering::Relaxed),
                );
            }

            let secrets = find_secrets(
                &sds_scanner,
                &secrets_rules,
                GIT_HISTORY_BLOB_PLACEHOLDER,
                &content,
                options,
            );
            if secrets.is_empty() {
                None
            } else {
                secret_blobs.fetch_add(1, Ordering::Relaxed);
                Some((oid, secrets))
            }
        })
        .collect();

    let found: HashMap<Oid, Vec<SecretResult>> = collected.into_iter().collect();
    eprintln!(
        "[git-history] pass1 done: examined {} objects, scanned {} blobs in {:.1}s, {} secret-bearing blobs",
        objects_examined.load(Ordering::Relaxed),
        blobs_scanned.load(Ordering::Relaxed),
        t_scan.elapsed().as_secs_f64(),
        found.len(),
    );

    Ok(found)
}

/// Pass 2: map a (small) set of secret-bearing blob OIDs back to the (path,
/// introducing commit) pairs where they appear across all refs (branches, tags,
/// remote-tracking branches, stash).
///
/// git keeps no reverse index from blob to commits, so attribution requires a
/// history traversal. We shell out to a single `git log --all --raw` pass and
/// stream-parse it, keeping only deltas whose new blob OID is one of the (rare)
/// `targets`. `--all` walks every ref (branches, tags, remote-tracking branches,
/// stash), so a secret living only in a tagged release or a remote branch is still
/// attributed rather than silently dropped at emit time. git's diff machinery
/// (commit-graph + tree-OID subtree skipping) walks
/// the whole history in tens of seconds, where the equivalent libgit2 per-commit
/// `diff_tree_to_tree` loop is orders of magnitude slower.
///
/// `git log` output is newest-first, so for each (blob, path) we overwrite the
/// recorded commit as we stream; the final value is the oldest (introducing) commit.
/// All distinct paths are collected per target blob (a blob may live at several paths).
fn attribute_blobs_to_paths(
    source_directory: &str,
    targets: &HashSet<Oid>,
) -> anyhow::Result<HashMap<Oid, HashMap<String, BlobOccurrence>>> {
    use std::io::BufRead;

    let mut registry: HashMap<Oid, HashMap<String, BlobOccurrence>> = HashMap::new();
    if targets.is_empty() {
        return Ok(registry);
    }
    // Hex strings for matching against the `git log --raw` blob OIDs.
    let target_hex: HashSet<String> = targets.iter().map(|o| o.to_string()).collect();

    eprintln!(
        "[git-history] pass2: attributing {} secret-bearing blobs via 'git log --raw'",
        targets.len()
    );
    let t_walk = std::time::Instant::now();

    let args = [
        "-c",
        "core.quotePath=false",
        "log",
        "--all",
        "--raw",
        "--no-renames",
        "--no-abbrev",
        "--format=C %H",
    ];

    let mut child = std::process::Command::new("git")
        .current_dir(source_directory)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let stdout = child.stdout.take().expect("git stdout is piped");
    let reader = std::io::BufReader::new(stdout);

    let mut current_commit: Option<Oid> = None;
    let mut commit_count: u64 = 0;
    for line in reader.lines() {
        let line = line?;
        // Commit marker line: "C <full-sha>".
        if let Some(sha) = line.strip_prefix("C ") {
            current_commit = Oid::from_str(sha.trim()).ok();
            commit_count += 1;
            if commit_count.is_multiple_of(200_000) {
                eprintln!(
                    "[git-history] pass2: parsed {} commits ({:.0}/s), {}/{} target blobs attributed",
                    commit_count,
                    commit_count as f64 / t_walk.elapsed().as_secs_f64().max(0.001),
                    registry.len(),
                    targets.len(),
                );
            }
            continue;
        }
        // Raw diff line: ":<mode> <mode> <oldsha> <newsha> <status>\t<path>".
        let Some((meta, path)) = line.split_once('\t') else {
            continue;
        };
        if !meta.starts_with(':') {
            continue;
        }
        let fields: Vec<&str> = meta.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let Some(commit) = current_commit else {
            continue;
        };
        let (old_sha, new_sha) = (fields[2], fields[3]);

        // NEW side (add/modify): the blob is present at this path as of this commit.
        // The stream is newest-first, so overwriting keeps the OLDEST such commit as
        // the introducing commit. A finding is only ever reported for a path with an
        // introducing commit (a reachable add).
        if target_hex.contains(new_sha) {
            if let Ok(blob_oid) = Oid::from_str(new_sha) {
                let occ = find_or_create_occurrence(&mut registry, blob_oid, path);
                occ.introduced_at = Some(commit);
            }
        }
        // OLD side (delete/modify): the blob left this path at this commit. Keep the
        // FIRST seen (newest) as the removal commit. This only ever ENRICHES an
        // occurrence with a removal commit; occurrences that never get an
        // introducing commit are dropped at emit time, so this does not resurrect
        // unreachable-origin paths.
        if target_hex.contains(old_sha) {
            if let Ok(blob_oid) = Oid::from_str(old_sha) {
                let occ = find_or_create_occurrence(&mut registry, blob_oid, path);
                if occ.removed_at.is_none() {
                    occ.removed_at = Some(commit);
                }
            }
        }
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "`git log` exited with status {status} during history attribution"
        ));
    }

    eprintln!(
        "[git-history] pass2 done: parsed {} commits in {:.1}s, attributed {}/{} blobs",
        commit_count,
        t_walk.elapsed().as_secs_f64(),
        registry.len(),
        targets.len(),
    );

    Ok(registry)
}

/// Scan git history for secrets that are not present at the current branch HEAD.
///
/// Two passes:
/// 1. scan every unique blob in the object database for secrets (scan_all_blobs_for_secrets)
/// 2. for the rare blobs that contained a secret, reverse-map them to their (path, introducing commit) occurrences (attribute_blobs_to_paths).
///
/// HEAD findings are already covered by the normal secret_analysis(), so (blob, path) pairs present at HEAD are excluded here.
pub fn git_history_secret_analysis(
    run_config: &RunConfiguration,
    secrets_rules: &[SecretRule],
    options: &AnalysisOptions,
) -> anyhow::Result<Vec<HistoricalSecretResult>> {
    let repo = Repository::open(&run_config.source_directory)?;

    // Pass 1: scan all unique blobs.
    let secret_blobs = scan_all_blobs_for_secrets(&repo, run_config, secrets_rules, options)?;
    if secret_blobs.is_empty() {
        return Ok(Vec::new());
    }

    // Pass 2: attribute the secret-bearing blobs to their (path, commit) pairs.
    let targets: HashSet<Oid> = secret_blobs.keys().copied().collect();
    let registry = attribute_blobs_to_paths(&run_config.source_directory, &targets)?;
    let head_blob_paths = collect_head_blob_paths(&repo);

    let mut results: Vec<HistoricalSecretResult> = Vec::new();
    for (blob_oid, occurrences) in &registry {
        let Some(secrets) = secret_blobs.get(blob_oid) else {
            continue;
        };
        for (path, occurrence) in occurrences {
            // Only report paths with a reachable introducing commit. An occurrence
            // seen only via a deletion (no reachable add) is skipped.
            let Some(introduced_at) = occurrence.introduced_at else {
                continue;
            };
            // Skip pairs present at HEAD at the same path (covered by normal scan).
            if head_blob_paths.contains(&(*blob_oid, path.clone())) {
                continue;
            }
            // Per-path file filtering (deferred from pass 1, which had no path).
            if should_ignore_file_for_secret(Path::new(path)) {
                continue;
            }
            for secret in secrets {
                results.push(HistoricalSecretResult {
                    inner: secret.clone_with_path(path),
                    introducing_commit_sha: introduced_at,
                    removed_at_sha: occurrence.removed_at,
                });
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod git_history_tests {
    use super::*;
    use cli::model::run_configuration::RunConfiguration;
    use git2::{Oid, Repository};
    use std::collections::HashSet;
    use std::path::Path;

    fn init_repo(path: &Path) -> Repository {
        Repository::init(path).unwrap()
    }

    /// Write `files` (path, content), stage `deletes`, and create a commit on HEAD.
    fn commit(repo: &Repository, files: &[(&str, &str)], deletes: &[&str], msg: &str) -> Oid {
        let workdir = repo.workdir().unwrap().to_path_buf();
        let mut index = repo.index().unwrap();
        for (p, content) in files {
            let full = workdir.join(p);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&full, content).unwrap();
            index.add_path(Path::new(p)).unwrap();
        }
        for p in deletes {
            let _ = std::fs::remove_file(workdir.join(p));
            index.remove_path(Path::new(p)).unwrap();
        }
        index.write().unwrap();
        let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();
        let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &parents)
            .unwrap()
    }

    fn blob_oid(repo: &Repository, content: &str) -> Oid {
        repo.blob(content.as_bytes()).unwrap()
    }

    fn config_with_rule(repo_dir: &str) -> (RunConfiguration, Vec<SecretRule>) {
        use kernel::model::common::OutputFormat;
        use secrets::model::secret_rule::{RulePriority, SecretRule};

        let rule = SecretRule {
            id: "test-rule".to_string(),
            name: "test-rule".to_string(),
            sds_id: "71A7A0ED-DD03-45C5-9C2E-56B30CB566E0".to_string(),
            description: "test".to_string(),
            pattern: "SECRETVALUE[0-9]+".to_string(),
            default_included_keywords: vec![],
            default_excluded_keywords: vec![],
            look_ahead_character_count: Some(30),
            priority: RulePriority::Medium,
            validators: Some(vec![]),
            validators_v2: None,
            match_validation: None,
            pattern_capture_groups: vec![],
            is_supporting_rule: false,
        };
        let run_config = RunConfiguration {
            use_debug: false,
            configuration_method: None,
            source_directory: repo_dir.to_string(),
            source_subdirectories: vec![],
            output_format: OutputFormat::Sarif,
            output_file: String::new(),
            num_cpus: 2,
            use_staging: false,
            static_analysis_enabled: false,
            secrets_enabled: true,
        };
        (run_config, vec![rule])
    }

    /// A blob removed before HEAD is attributed to the single path/commit that
    /// introduced it.
    #[test]
    fn attribute_single_path() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        let c1 = commit(&repo, &[("config.txt", "SECRETVALUE123\n")], &[], "add");
        let secret = blob_oid(&repo, "SECRETVALUE123\n");
        commit(&repo, &[("config.txt", "clean\n")], &[], "scrub");

        let targets: HashSet<Oid> = [secret].into_iter().collect();
        let reg = attribute_blobs_to_paths(dir.path().to_str().unwrap(), &targets).unwrap();
        let occ = reg.get(&secret).expect("secret blob attributed");
        assert_eq!(occ.len(), 1);
        let (path, occurrence) = occ.iter().next().unwrap();
        assert_eq!(path, "config.txt");
        assert_eq!(occurrence.introduced_at, Some(c1));
    }

    /// The same content at two different paths is reported at BOTH paths, each with
    /// its own introducing commit.
    #[test]
    fn attribute_multi_path() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        let c1 = commit(&repo, &[("a.txt", "DUP123\n")], &[], "add a");
        let c2 = commit(&repo, &[("b.txt", "DUP123\n")], &[], "add b");
        let dup = blob_oid(&repo, "DUP123\n");

        let targets: HashSet<Oid> = [dup].into_iter().collect();
        let reg = attribute_blobs_to_paths(dir.path().to_str().unwrap(), &targets).unwrap();
        let occ = reg.get(&dup).unwrap();
        let mut paths: Vec<_> = occ
            .iter()
            .map(|(p, o)| (p.as_str(), o.introduced_at))
            .collect();
        paths.sort();
        assert_eq!(paths, vec![("a.txt", Some(c1)), ("b.txt", Some(c2))]);
    }

    /// One blob (empty content) duplicated across many paths in a single (root)
    /// commit: all paths are recorded, no quadratic blowup, no panic.
    #[test]
    fn attribute_high_fanout() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        let files: Vec<(String, String)> = (0..50)
            .map(|i| (format!("d{i}/__init__.py"), String::new()))
            .collect();
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        let c1 = commit(&repo, &refs, &[], "many empty files");
        let empty = blob_oid(&repo, "");

        let targets: HashSet<Oid> = [empty].into_iter().collect();
        let reg = attribute_blobs_to_paths(dir.path().to_str().unwrap(), &targets).unwrap();
        let occ = reg.get(&empty).unwrap();
        assert_eq!(occ.len(), 50);
        assert!(occ.values().all(|o| o.introduced_at == Some(c1)));
    }

    /// A moved file (delete old path + add new path) is attributed at BOTH paths:
    /// the new path via the add, the old path via the delete (matching the delta's
    /// OLD blob OID). The old path keeps its true introducing commit.
    #[test]
    fn attribute_move_records_both_paths() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        let c1 = commit(&repo, &[("a.txt", "MOVED123\n")], &[], "add a");
        let c2 = commit(&repo, &[("b.txt", "MOVED123\n")], &["a.txt"], "move a -> b");
        let blob = blob_oid(&repo, "MOVED123\n");

        let targets: HashSet<Oid> = [blob].into_iter().collect();
        let reg = attribute_blobs_to_paths(dir.path().to_str().unwrap(), &targets).unwrap();
        let occ = reg.get(&blob).expect("moved blob attributed");
        let mut paths: Vec<_> = occ
            .iter()
            .map(|(p, o)| (p.as_str(), o.introduced_at, o.removed_at))
            .collect();
        paths.sort();
        // a.txt: introduced at c1 (oldest add wins over the c2 delete sighting) and
        // removed at c2 (the move deletes it). b.txt: introduced at c2, still present.
        assert_eq!(
            paths,
            vec![("a.txt", Some(c1), Some(c2)), ("b.txt", Some(c2), None),]
        );
    }

    /// End-to-end: a secret removed before HEAD is reported as historical with the
    /// correct introducing SHA, while a secret still present at HEAD (same blob+path)
    /// is NOT reported (it is covered by the normal HEAD scan).
    #[test]
    fn history_scan_excludes_head_and_tags_historical() {
        let dir = tempfile::tempdir().unwrap();
        let repo = init_repo(dir.path());
        let c1 = commit(
            &repo,
            &[
                ("secret.txt", "SECRETVALUE123\n"),
                ("keep.txt", "SECRETVALUE999\n"),
            ],
            &[],
            "add secrets",
        );
        // Scrub secret.txt; keep.txt (with its secret) stays at HEAD.
        let c2 = commit(&repo, &[("secret.txt", "clean\n")], &[], "scrub");

        let (run_config, secrets_rules) = config_with_rule(dir.path().to_str().unwrap());
        let options = AnalysisOptions::default();
        let results = git_history_secret_analysis(&run_config, &secrets_rules, &options).unwrap();

        assert_eq!(results.len(), 1, "only the removed secret is historical");
        let r = &results[0];
        assert_eq!(r.inner.filename, "secret.txt");
        assert_eq!(r.introducing_commit_sha, c1);
        // secret.txt's secret was scrubbed in c2, so it is the removal commit.
        assert_eq!(r.removed_at_sha, Some(c2));
        assert!(
            results.iter().all(|x| x.inner.filename != "keep.txt"),
            "a secret still present at HEAD must not be reported as historical"
        );
    }
}
