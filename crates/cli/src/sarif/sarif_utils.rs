use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

use crate::constants::{SARIF_PROPERTY_DATADOG_FINGERPRINT, SARIF_PROPERTY_SHA};
use anyhow::Result;
use base64::Engine;
use common::model::position::Position;
use common::model::position::PositionBuilder;
use git2::{BlameOptions, Repository};
use kernel::classifiers::ArtifactClassification;
use kernel::constants::CARGO_VERSION;
use kernel::model::rule::{RuleCategory, RuleSeverity};
use kernel::model::violation::Violation;
use kernel::model::{
    rule::{Rule, RuleResult},
    violation::{Edit, EditType},
};
use path_slash::PathExt;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use secrets::model::secret_result::{SecretResult, SecretValidationStatus};
use secrets::model::secret_rule::SecretRule;
use serde_sarif::sarif::{
    self, Artifact, ArtifactBuilder, ArtifactChangeBuilder, ArtifactLocationBuilder, FixBuilder,
    LocationBuilder, MessageBuilder, PhysicalLocationBuilder, PropertyBagBuilder, RegionBuilder,
    Replacement, ReportingDescriptor, Result as SarifResult, ResultBuilder, RunBuilder, Sarif,
    SarifBuilder, Tool, ToolBuilder, ToolComponent, ToolComponentBuilder,
};

use crate::file_utils::get_fingerprint_for_violation;
use crate::model::cli_configuration::CliConfiguration;
use crate::model::datadog_api::DiffAwareData;
use crate::rule_utils::map_priority_to_severity;
use crate::sarif::sarif_utils::SarifViolation::{Secret, StaticAnalysis};

trait IntoSarif {
    type SarifType;

    fn into_sarif(self) -> Self::SarifType;
}

/// The `SarifReportMetadata` structure contains all metadata being added to the sarif report.
/// Those metadata is being added as property is being used to enhance the generation
/// of the SARIF report.
pub struct SarifReportMetadata {
    pub add_git_info: bool,
    pub debug: bool,
    pub config_digest: String,
    pub diff_aware_parameters: Option<DiffAwareData>,
    pub execution_time_secs: u64,
}

#[derive(Debug, Clone)]
pub enum SarifRule {
    StaticAnalysis(Box<Rule>),
    SecretRule(Box<SecretRule>),
}

impl SarifRule {
    /// The rule identifier, which is how we identify a rule in the SARIF file and find it's index
    fn id(&self) -> &str {
        match self {
            SarifRule::StaticAnalysis(r) => r.name.as_str(),
            SarifRule::SecretRule(r) => r.id.as_str(),
        }
    }

    fn category(&self) -> RuleCategory {
        match self {
            SarifRule::StaticAnalysis(r) => r.category,
            SarifRule::SecretRule(_) => RuleCategory::Security,
        }
    }

    fn cwe(&self) -> Option<&str> {
        match self {
            SarifRule::StaticAnalysis(r) => r.cwe.as_deref(),
            SarifRule::SecretRule(_) => None,
        }
    }

    fn severity(&self) -> RuleSeverity {
        match self {
            SarifRule::StaticAnalysis(r) => r.severity,
            SarifRule::SecretRule(r) => map_priority_to_severity(r.priority),
        }
    }

    fn rule_type_tag(kind: &'static str) -> String {
        format!("DATADOG_RULE_TYPE:{}", kind)
    }

    fn is_testing(&self) -> bool {
        match self {
            SarifRule::StaticAnalysis(r) => r.is_testing,
            SarifRule::SecretRule(_) => false,
        }
    }
}

impl IntoSarif for &SarifRule {
    type SarifType = ReportingDescriptor;

    fn into_sarif(self) -> Self::SarifType {
        match self {
            SarifRule::StaticAnalysis(r) => r.into_sarif(),
            SarifRule::SecretRule(r) => r.into_sarif(),
        }
    }
}

impl From<Rule> for SarifRule {
    fn from(value: Rule) -> Self {
        Self::StaticAnalysis(Box::new(value))
    }
}

impl From<SecretRule> for SarifRule {
    fn from(value: SecretRule) -> Self {
        Self::SecretRule(Box::new(value))
    }
}

/// Generic representation of a violation for both static analysis and secrets
#[derive(Debug, Clone)]
pub enum SarifViolation {
    StaticAnalysis(Violation),
    Secret(Violation, SecretValidationStatus),
}

impl SarifViolation {
    fn get_violation(&self) -> &Violation {
        match self {
            StaticAnalysis(v) => v,
            Secret(v, _) => v,
        }
    }

    fn get_properties(&self) -> Vec<String> {
        if let Secret(_, validation_status) = &self {
            let status = match validation_status {
                SecretValidationStatus::NotValidated => "NOT_VALIDATED",
                SecretValidationStatus::Valid => "VALID",
                SecretValidationStatus::Invalid => "INVALID",
                SecretValidationStatus::ValidationError => "VALIDATION_ERROR",
                SecretValidationStatus::NotAvailable => "NOT_AVAILABLE",
            };
            vec![format!("DATADOG_SECRET_VALIDATION_STATUS:{}", status).to_string()]
        } else {
            vec![]
        }
    }
}

#[derive(Debug, Clone)]
pub enum SarifRuleResult {
    StaticAnalysis(RuleResult),
    Secret(SecretResult),
}

impl SarifRuleResult {
    fn violations(&self) -> Vec<SarifViolation> {
        match self {
            SarifRuleResult::StaticAnalysis(r) => r
                .violations
                .iter()
                .map(|v| StaticAnalysis(v.clone()))
                .collect::<Vec<SarifViolation>>(),
            SarifRuleResult::Secret(secret_result) => secret_result
                .matches
                .iter()
                .map(|r| {
                    let severity = match &r.validation_status {
                        SecretValidationStatus::NotValidated => RuleSeverity::Notice,
                        SecretValidationStatus::Valid => RuleSeverity::Error,
                        SecretValidationStatus::Invalid => RuleSeverity::None,
                        SecretValidationStatus::ValidationError => RuleSeverity::Warning,
                        SecretValidationStatus::NotAvailable => RuleSeverity::Error,
                    };

                    Secret(
                        Violation {
                            start: r.start,
                            end: r.end,
                            message: secret_result.message.clone(),
                            severity,
                            category: RuleCategory::Security,
                            fixes: vec![],
                            taint_flow: None,
                        },
                        r.validation_status,
                    )
                })
                .collect::<Vec<SarifViolation>>(),
        }
    }

    /// Returns the operating-system dependent (un-normalized) version of this path.
    fn unnormalized_path_str(&self) -> &str {
        match self {
            SarifRuleResult::StaticAnalysis(r) => &r.filename,
            SarifRuleResult::Secret(r) => &r.filename,
        }
    }

    /// Returns the file path for this result as a slash path. See [`as_slash_path`] for documentation.
    fn slash_path_str(&self) -> std::borrow::Cow<'_, str> {
        as_slash_path(match self {
            SarifRuleResult::StaticAnalysis(r) => &r.filename,
            SarifRuleResult::Secret(r) => &r.filename,
        })
    }

    fn rule_name(&self) -> &str {
        match self {
            SarifRuleResult::StaticAnalysis(r) => r.rule_name.as_str(),
            SarifRuleResult::Secret(r) => r.rule_name.as_str(),
        }
    }

    fn rule_id(&self) -> &str {
        match self {
            SarifRuleResult::StaticAnalysis(r) => r.rule_name.as_str(),
            SarifRuleResult::Secret(r) => r.rule_id.as_str(),
        }
    }
}

impl TryFrom<RuleResult> for SarifRuleResult {
    type Error = String;

    fn try_from(value: RuleResult) -> std::result::Result<Self, Self::Error> {
        if Path::new(&value.filename).is_absolute() {
            Err(format!("path `{}` must be relative", &value.filename))
        } else {
            Ok(Self::StaticAnalysis(value))
        }
    }
}

impl TryFrom<SecretResult> for SarifRuleResult {
    type Error = String;

    fn try_from(value: SecretResult) -> std::result::Result<Self, Self::Error> {
        if Path::new(&value.filename).is_absolute() {
            Err(format!("path `{}` must be relative", &value.filename))
        } else {
            Ok(Self::Secret(value))
        }
    }
}

// Options to use when to generate the SARIF reports.
// if `add_git_info` is true, the git_repo should not be
// optional and will be used to get the SHA of the violations.
#[derive(Clone)]
pub struct SarifGenerationOptions {
    pub add_git_info: bool,
    pub git_repo: Option<Rc<Repository>>,
    pub debug: bool,
    pub config_digest: String,
    pub diff_aware_parameters: Option<DiffAwareData>,
    pub repository_directory: String,
    pub execution_time_secs: u64,
}

impl IntoSarif for &SecretRule {
    type SarifType = sarif::ReportingDescriptor;

    fn into_sarif(self) -> Self::SarifType {
        let mut builder = sarif::ReportingDescriptorBuilder::default();
        builder.id(&self.id);

        builder.name(&self.name);

        let description = sarif::MultiformatMessageStringBuilder::default()
            .text(std::str::from_utf8(self.description.as_bytes()).unwrap())
            .build()
            .expect("secret rules should have a description");
        builder.full_description(description);

        if !self.name.is_empty() {
            let short_description_text = sarif::MultiformatMessageStringBuilder::default()
                .text(std::str::from_utf8(self.name.as_bytes()).unwrap())
                .build()
                .unwrap();
            builder.short_description(short_description_text);
        }

        let props = PropertyBagBuilder::default()
            .tags(vec![
                SarifRule::rule_type_tag("SECRET"),
                format!("DATADOG_SDS_ID:{}", self.sds_id),
            ])
            .build()
            .unwrap();
        builder.properties(props);

        builder.build().unwrap()
    }
}

impl IntoSarif for &Rule {
    type SarifType = sarif::ReportingDescriptor;

    fn into_sarif(self) -> Self::SarifType {
        let mut builder = sarif::ReportingDescriptorBuilder::default();
        builder.id(&self.name);

        if let Some(d) = self.description_base64.as_ref() {
            let decrypted_description = base64::engine::general_purpose::STANDARD
                .decode(d.as_bytes())
                .unwrap();
            let text_description =
                std::str::from_utf8(&decrypted_description).unwrap_or("invalid full description");
            let text = sarif::MultiformatMessageStringBuilder::default()
                .text(std::str::from_utf8(text_description.as_bytes()).unwrap())
                .build()
                .unwrap();
            builder.full_description(text);
        }

        if let Some(d) = self.short_description_base64.as_ref() {
            let decrypted_description = base64::engine::general_purpose::STANDARD
                .decode(d.as_bytes())
                .unwrap();
            let text_description =
                std::str::from_utf8(&decrypted_description).unwrap_or("invalid short description");
            let text = sarif::MultiformatMessageStringBuilder::default()
                .text(std::str::from_utf8(text_description.as_bytes()).unwrap())
                .build()
                .unwrap();
            builder.short_description(text);
        }

        let mut tags = vec![SarifRule::rule_type_tag("STATIC_ANALYSIS")];
        if let Some(cwe) = self.cwe.as_ref() {
            tags.push(format!("CWE:{}", cwe));
        }
        if self.is_testing {
            tags.push("DATADOG_TESTING:true".to_string());
        }
        let props = PropertyBagBuilder::default().tags(tags).build().unwrap();
        builder.properties(props);

        builder.help_uri(self.get_url()).build().unwrap()
    }
}

// TODO: Error handling
impl IntoSarif for &Edit {
    type SarifType = sarif::Replacement;

    fn into_sarif(self) -> Self::SarifType {
        match self.edit_type {
            EditType::Add => sarif::ReplacementBuilder::default()
                .deleted_region(
                    sarif::RegionBuilder::default()
                        .start_line(self.start.line)
                        .start_column(self.start.col)
                        .end_line(self.start.line)
                        .end_column(self.start.col)
                        .build()
                        .unwrap(),
                )
                .inserted_content(
                    sarif::ArtifactContentBuilder::default()
                        .text(self.content.as_ref().unwrap())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
            EditType::Remove => sarif::ReplacementBuilder::default()
                .deleted_region(
                    sarif::RegionBuilder::default()
                        .start_line(self.start.line)
                        .start_column(self.start.col)
                        .end_line(
                            self.end
                                .unwrap_or(
                                    PositionBuilder::default().line(0).col(0).build().unwrap(),
                                )
                                .line,
                        )
                        .end_column(
                            self.end
                                .unwrap_or(
                                    PositionBuilder::default().line(0).col(0).build().unwrap(),
                                )
                                .col,
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
            EditType::Update => sarif::ReplacementBuilder::default()
                .deleted_region(
                    sarif::RegionBuilder::default()
                        .start_line(self.start.line)
                        .start_column(self.start.col)
                        .end_line(
                            self.end
                                .unwrap_or(
                                    PositionBuilder::default().line(0).col(0).build().unwrap(),
                                )
                                .line,
                        )
                        .end_column(
                            self.end
                                .unwrap_or(
                                    PositionBuilder::default().line(0).col(0).build().unwrap(),
                                )
                                .col,
                        )
                        .build()
                        .unwrap(),
                )
                .inserted_content(
                    sarif::ArtifactContentBuilder::default()
                        .text(self.content.as_ref().unwrap())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        }
    }
}

// Generate the tool section that reports all the rules being run
fn generate_tool_section(rules: &[SarifRule], options: &SarifGenerationOptions) -> Result<Tool> {
    let mut tags = vec![];
    tags.push(format!(
        "DATADOG_DIFF_AWARE_CONFIG_DIGEST:{}",
        options.config_digest
    ));
    tags.push(format!(
        "DATADOG_EXECUTION_TIME_SECS:{}",
        options.execution_time_secs
    ));

    // if diff-aware is enabled and we got diff-aware data from the backend, we add it in the sarif file
    if let Some(diff_aware) = &options.diff_aware_parameters {
        tags.push("DATADOG_DIFF_AWARE_ENABLED:true".to_string());
        tags.push(format!(
            "DATADOG_DIFF_AWARE_BASE_SHA:{}",
            diff_aware.base_sha
        ));
        diff_aware.files.iter().for_each(|f| {
            tags.push(format!("DATADOG_DIFF_AWARE_FILE:{}", f));
        })
    } else {
        tags.push("DATADOG_DIFF_AWARE_ENABLED:false".to_string());
    }

    let driver: ToolComponent = ToolComponentBuilder::default()
        .name("datadog-static-analyzer")
        .version(CARGO_VERSION)
        .information_uri("https://www.datadoghq.com")
        .rules(
            rules
                .iter()
                .map(|e| e.into_sarif())
                .collect::<Vec<ReportingDescriptor>>(),
        )
        .properties(PropertyBagBuilder::default().tags(tags).build().unwrap())
        .build()?;

    Ok(ToolBuilder::default().driver(driver).build()?)
}

fn is_valid_position(position: &Position) -> bool {
    position.line > 0 && position.col > 0
}

/// Check that the violation is valid and must be included
fn is_valid_violation(violation: &Violation) -> bool {
    if !is_valid_position(&violation.start) || !is_valid_position(&violation.end) {
        return false;
    }

    // make sure that no violation has an invalid fix
    violation.fixes.iter().all(|f| {
        f.edits.iter().all(|e| {
            is_valid_position(&e.start) && e.end.map(|p| is_valid_position(&p)).unwrap_or(true)
        })
    })
}

/// Convert our severity enumeration into the corresponding SARIF values.
/// The main discrepancy here is that Notice maps to note.
/// See [this document](https://github.com/oasis-tcs/sarif-spec/blob/main/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json#L1566)
/// for the full SARIF standard.
fn get_level_from_severity(severity: RuleSeverity) -> String {
    match severity {
        RuleSeverity::Notice => "note",
        RuleSeverity::Warning => "warning",
        RuleSeverity::Error => "error",
        _ => "none",
    }
    .to_string()
}

/// Get the latest commit id/sha for a file/line. This is done to know the latest SHA for a line with
/// a violation. Note that this function performs a `git blame` and can take significant time.
/// Take the file/line of the SHA to get and return the SHA if found.
fn get_sha_for_line(
    filename: &str,
    line: usize,
    generation_options: &SarifGenerationOptions,
) -> Option<String> {
    if let Some(git_repo) = generation_options.git_repo.as_ref() {
        if generation_options.debug {
            eprint!(
                "[get_sha_for_line] Getting SHA for file {}, line {}: ",
                filename, line
            );
        }

        let mut blame_options = BlameOptions::default();
        let blame_res = git_repo.blame_file(Path::new(filename), Some(&mut blame_options));

        if let Ok(blame) = blame_res {
            if let Some(hunk) = blame.get_line(line) {
                let commit_id = hunk.final_commit_id().to_string();

                if generation_options.debug {
                    eprintln!("found ({})", commit_id);
                }
                return Some(commit_id);
            } else {
                if generation_options.debug {
                    eprintln!("hunk not found");
                }
                return None;
            }
        }

        if generation_options.debug {
            eprintln!(" cannot get git blame info at {}:{}", filename, line)
        }
        None
    } else {
        None
    }
}

/// Normalizes the provided file path by percent encoding it. See [`utf8_percent_encode`] for
/// further documentation.
fn percent_encode_path(file_path: &str) -> std::borrow::Cow<'_, str> {
    const FRAGMENT: &AsciiSet = &CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'`')
        .add(b'[')
        .add(b']')
        .add(b'#')
        .add(b'%');

    utf8_percent_encode(file_path, FRAGMENT).into()
}

/// Generate the tool section that reports all the rules being run
///
/// `artifacts_kv` should contain exactly one artifact for each unnormalized string path in `rules_results`.
fn generate_results(
    rules: &[SarifRule],
    rules_results: &[SarifRuleResult],
    options_orig: &SarifGenerationOptions,
    artifacts_kv: &[(&str, Artifact)],
) -> Result<Vec<SarifResult>> {
    // (A lookup should be, on-balance, faster)
    let artifacts = artifacts_kv
        .iter()
        .map(|(k, v)| (*k, v))
        .collect::<HashMap<_, _>>();

    rules_results
        .iter()
        .flat_map(|rule_result| {
            let artifact_loc = artifacts
                .get(rule_result.unnormalized_path_str())
                .as_ref()
                .expect("artifacts should be comprehensive")
                .location
                .as_ref()
                .expect("artifact should always have location");
            // if we find the rule for this violation, get the id, level and category
            let mut result_builder = ResultBuilder::default();
            let mut tags = vec![];

            if let Some(rule_index) = rules.iter().position(|r| r.id() == rule_result.rule_id()) {
                let rule = &rules[rule_index];
                let category = format!("DATADOG_CATEGORY:{}", rule.category()).to_uppercase();
                tags.push(category);

                result_builder.rule_index(i64::try_from(rule_index).unwrap());
                result_builder.level(get_level_from_severity(rule.severity()));

                // If there is a CWE, add it
                if let Some(cwe) = rule.cwe() {
                    tags.push(format!("CWE:{}", cwe));
                }

                // If the rule is a test, add a tag
                if rule.is_testing() {
                    tags.push("DATADOG_TESTING:true".to_string());
                }
            }

            let options = options_orig.clone();
            let violations = rule_result.violations();
            violations
                .into_iter()
                .filter(|sarif_violation| {
                    let is_valid = is_valid_violation(sarif_violation.get_violation());
                    if !is_valid && options_orig.debug {
                        eprintln!(
                            "Invalid violations detected, check the rule {}",
                            rule_result.rule_name()
                        )
                    }
                    is_valid
                })
                .map(move |sarif_violation| {
                    let violation = sarif_violation.get_violation();
                    // if we find the rule for this violation, get the id, level and category
                    let location = LocationBuilder::default()
                        .physical_location(
                            PhysicalLocationBuilder::default()
                                .artifact_location(artifact_loc.clone())
                                .region(
                                    RegionBuilder::default()
                                        .start_line(violation.start.line)
                                        .start_column(violation.start.col)
                                        .end_line(violation.end.line)
                                        .end_column(violation.end.col)
                                        .build()?,
                                )
                                .build()?,
                        )
                        .build()?;

                    let fixes: Vec<sarif::Fix> = violation
                        .fixes
                        .iter()
                        .map(|fix| {
                            let replacements: Vec<Replacement> =
                                fix.edits.iter().map(IntoSarif::into_sarif).collect();

                            let changes = ArtifactChangeBuilder::default()
                                .artifact_location(artifact_loc.clone())
                                .replacements(replacements)
                                .build()?;
                            Ok(FixBuilder::default()
                                .description(
                                    MessageBuilder::default()
                                        .text(fix.description.clone())
                                        .build()?,
                                )
                                .artifact_changes(vec![changes])
                                .build()?)
                        })
                        .collect::<Result<Vec<_>>>()?;

                    let taint_code_flow: Result<_, anyhow::Error> = violation
                        .taint_flow
                        .as_ref()
                        .map(|regions| {
                            let last_idx = regions.len().saturating_sub(1);
                            let tf_locations = regions
                                .iter()
                                .enumerate()
                                .map(|(idx, region)| {
                                    let importance = if idx == 0 || idx == last_idx {
                                        "essential"
                                    } else {
                                        "important"
                                    };
                                    let region = sarif::RegionBuilder::default()
                                        .start_line(region.start.line)
                                        .start_column(region.start.col)
                                        .end_line(region.end.line)
                                        .end_column(region.end.col)
                                        .build()?;
                                    let location = sarif::LocationBuilder::default()
                                        .physical_location(
                                            sarif::PhysicalLocationBuilder::default()
                                                .artifact_location(artifact_loc.clone())
                                                .region(region)
                                                .build()?,
                                        )
                                        .build()?;
                                    Ok::<_, anyhow::Error>(
                                        sarif::ThreadFlowLocationBuilder::default()
                                            .location(location)
                                            .importance(importance)
                                            .build()?,
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            if tf_locations.len() < 2 {
                                return Err(anyhow::Error::msg(
                                    "taint flow must have at least two regions",
                                ));
                            }
                            let thread_flow = sarif::ThreadFlowBuilder::default()
                                .locations(tf_locations)
                                .build()?;
                            Ok(sarif::CodeFlowBuilder::default()
                                .thread_flows(&[thread_flow])
                                .build()?)
                        })
                        .transpose();
                    let taint_code_flow = taint_code_flow?;

                    let sha_option = if options.add_git_info {
                        get_sha_for_line(
                            &rule_result.slash_path_str(),
                            violation.start.line as usize,
                            &options,
                        )
                    } else {
                        None
                    };

                    let fingerprint_option = get_fingerprint_for_violation(
                        rule_result.rule_name().to_string(),
                        violation,
                        Path::new(options.repository_directory.as_str()),
                        Path::new(rule_result.slash_path_str().as_ref()),
                        options.debug,
                    );

                    let partial_fingerprints: BTreeMap<String, String> =
                        match (sha_option, fingerprint_option) {
                            (Some(sha), Some(fp)) => BTreeMap::from([
                                (SARIF_PROPERTY_SHA.to_string(), sha),
                                (SARIF_PROPERTY_DATADOG_FINGERPRINT.to_string(), fp),
                            ]),
                            (None, Some(fp)) => BTreeMap::from([(
                                SARIF_PROPERTY_DATADOG_FINGERPRINT.to_string(),
                                fp,
                            )]),
                            (Some(sha), None) => {
                                BTreeMap::from([(SARIF_PROPERTY_SHA.to_string(), sha)])
                            }
                            _ => BTreeMap::new(),
                        };

                    let mut sarif_result = result_builder.clone();

                    sarif_result
                        .rule_id(rule_result.rule_id())
                        .locations([location])
                        .fixes(fixes)
                        .message(
                            MessageBuilder::default()
                                .text(violation.message.clone())
                                .build()
                                .unwrap(),
                        )
                        .properties(
                            PropertyBagBuilder::default()
                                .tags([tags.clone(), sarif_violation.get_properties()].concat())
                                .build()
                                .unwrap(),
                        )
                        .partial_fingerprints(partial_fingerprints);
                    if let Some(taint_code_flow) = taint_code_flow {
                        sarif_result.code_flows(&[taint_code_flow]);
                    };
                    Ok(sarif_result.build()?)
                })
        })
        .collect()
}

/// A property tag to indicate an [`ArtifactClassification`] where `is_test_file` is true.
const CLASSIFICATION_TEST_FILE: &str = "DATADOG_ARTIFACT_IS_TEST_FILE";

/// Returns a map of un-normalized string paths to their corresponding [`Artifact`] in the same
/// order as encountered in the `unnormalized_path_strs` iterator.
///
/// `path_metadata` should be a map from an un-normalized string to metadata.
fn extract_artifacts<'a>(
    unnormalized_path_strs: impl IntoIterator<Item = &'a str>,
    path_metadata: &HashMap<String, ArtifactClassification>,
) -> Vec<(&'a str, Artifact)> {
    let path_strs_iter = unnormalized_path_strs.into_iter();
    let iter_size_hint = path_strs_iter.size_hint().0;
    // A tuple with the _un-normalized string_ representation of a path and its corresponding Artifact.
    let mut artifacts = Vec::<(&str, Artifact)>::with_capacity(iter_size_hint);
    let mut seen_artifacts = HashSet::<&str>::with_capacity(iter_size_hint);

    for path_str in path_strs_iter {
        if !seen_artifacts.contains(path_str) {
            seen_artifacts.insert(path_str);

            let mut builder = ArtifactBuilder::default();
            let location = ArtifactLocationBuilder::default()
                // The ArtifactLocation uses a normalized form of the path
                .uri(percent_encode_path(as_slash_path(path_str).as_ref()))
                .build()
                .expect("all required fields should be present");
            builder.location(location);

            let mut tags: Vec<String> = vec![];
            if let Some(metadata) = path_metadata.get(path_str) {
                if metadata.is_test_file {
                    tags.push(CLASSIFICATION_TEST_FILE.to_string());
                }
            }
            if !tags.is_empty() {
                let properties = PropertyBagBuilder::default()
                    .tags(tags)
                    .build()
                    .expect("all required fields should be present");
                builder.properties(properties);
            }

            let artifact = builder
                .build()
                .expect("all required fields should be present");
            artifacts.push((path_str, artifact));
        }
    }
    artifacts
}

/// Generates a single-run SARIF report with the rules, results, and tool information used.
///
/// `path_metadata` should be a map from an un-normalized string to metadata.
pub fn generate_sarif_report(
    rules: &[SarifRule],
    rules_results: &[SarifRuleResult],
    directory: &String,
    tool_information: SarifReportMetadata,
    path_metadata: &HashMap<String, ArtifactClassification>,
) -> Result<Sarif> {
    // if we enable git info, we are then getting the repository object. We put that
    // into an `Arc` object to be able to clone the object.
    let repository: Option<Rc<Repository>> = if tool_information.add_git_info {
        let repo = Repository::open(directory.as_str());
        if repo.is_err() {
            eprintln!("Invalid Git repository in {}", directory);
            panic!("Please provide a valid Git repository or disable Git integration");
        }
        Some(Rc::new(repo.expect("cannot open repository")))
    } else {
        None
    };

    let options = SarifGenerationOptions {
        add_git_info: tool_information.add_git_info,
        git_repo: repository,
        debug: tool_information.debug,
        config_digest: tool_information.config_digest.clone(),
        diff_aware_parameters: tool_information.diff_aware_parameters.clone(),
        repository_directory: directory.clone(),
        execution_time_secs: tool_information.execution_time_secs,
    };

    let artifacts_kv = extract_artifacts(
        rules_results.iter().map(|res| res.unnormalized_path_str()),
        path_metadata,
    );

    let results = generate_results(rules, rules_results, &options, &artifacts_kv)?;
    let artifacts = artifacts_kv.into_iter().map(|kv| kv.1).collect::<Vec<_>>();

    let run = RunBuilder::default()
        .tool(generate_tool_section(rules, &options)?)
        .results(results)
        .artifacts(artifacts)
        .build()?;

    Ok(SarifBuilder::default()
        .version("2.1.0")
        .runs(vec![run])
        .build()?)
}

pub fn generate_sarif_file(
    configuration: &CliConfiguration,
    static_analysis_rule_results: Vec<RuleResult>,
    secrets_rule_results: Vec<SecretResult>,
    sarif_report_metadata: SarifReportMetadata,
    path_metadata: &HashMap<String, ArtifactClassification>,
) -> Result<String> {
    let static_rules_sarif: Vec<SarifRule> = configuration
        .rules
        .iter()
        .cloned()
        .map(|r| r.into())
        .collect();
    let secrets_rules_sarif: Vec<SarifRule> = configuration
        .secrets_rules
        .clone()
        .into_iter()
        .map(|r| r.into())
        .collect();
    let static_analysis_results = static_analysis_rule_results
        .into_iter()
        .map(SarifRuleResult::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::msg)?;
    let secret_results = secrets_rule_results
        .into_iter()
        .map(SarifRuleResult::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::msg)?;

    match generate_sarif_report(
        &[static_rules_sarif, secrets_rules_sarif].concat(),
        &[static_analysis_results, secret_results].concat(),
        &configuration.source_directory,
        sarif_report_metadata,
        path_metadata,
    ) {
        Ok(report) => {
            Ok(serde_json::to_string(&report).expect("error when getting the SARIF report"))
        }
        Err(err) => Err(err),
    }
}

/// Returns the file path for this result as a slash path, a path whose components are.
/// always separated by `/` and never `\`. Any non-Unicode sequences are replaced with `U+FFFD`.
fn as_slash_path(path_str: &str) -> std::borrow::Cow<'_, str> {
    Path::new(path_str).to_slash().expect("str should be utf-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::{assert_json_eq, assert_json_include};
    use common::model::position::{Position, PositionBuilder, Region};
    use kernel::model::violation::{Fix, Violation};
    use kernel::model::{
        common::Language,
        rule::{RuleBuilder, RuleCategory, RuleResultBuilder, RuleSeverity, RuleType},
        violation::{EditBuilder, EditType, FixBuilder as RosieFixBuilder, ViolationBuilder},
    };
    use secrets::model::secret_result::SecretResultMatch;
    use secrets::model::secret_rule::RulePriority;
    use serde_json::{from_str, Value};
    use valico::json_schema;

    /// Validate JSON data against the SARIF schema
    fn validate_data(v: &Value) -> bool {
        let j_schema = from_str(include_str!("sarif-schema-2.1.0.json")).unwrap();
        let mut scope = json_schema::Scope::new();
        let schema = scope.compile_and_return(j_schema, true).expect("schema");
        schema.validate(v).is_valid()
    }

    #[test]
    fn test_is_valid_violation() {
        // bad location in the violation location
        assert!(!is_valid_violation(&Violation {
            start: Position { line: 0, col: 1 },
            end: Position { line: 42, col: 42 },
            message: "bad stuff".to_string(),
            severity: RuleSeverity::Error,
            category: RuleCategory::BestPractices,
            fixes: vec![],
            taint_flow: None,
        }));

        // good location in the violation location and no fixes
        assert!(is_valid_violation(&Violation {
            start: Position { line: 1, col: 1 },
            end: Position { line: 42, col: 42 },
            message: "bad stuff".to_string(),
            severity: RuleSeverity::Error,
            category: RuleCategory::BestPractices,
            fixes: vec![],
            taint_flow: None,
        }));

        // bad location in the fixes location
        assert!(!is_valid_violation(&Violation {
            start: Position { line: 1, col: 1 },
            end: Position { line: 42, col: 42 },
            message: "bad stuff".to_string(),
            severity: RuleSeverity::Error,
            category: RuleCategory::BestPractices,
            fixes: vec![Fix {
                description: "fix".to_string(),
                edits: vec![Edit {
                    start: Position { line: 0, col: 1 },
                    end: None,
                    edit_type: EditType::Add,
                    content: Some("foo".to_string())
                }]
            }],
            taint_flow: None,
        }));

        // good location everywhere
        assert!(is_valid_violation(&Violation {
            start: Position { line: 1, col: 1 },
            end: Position { line: 42, col: 42 },
            message: "bad stuff".to_string(),
            severity: RuleSeverity::Error,
            category: RuleCategory::BestPractices,
            fixes: vec![Fix {
                description: "fix".to_string(),
                edits: vec![Edit {
                    start: Position { line: 1, col: 1 },
                    end: None,
                    edit_type: EditType::Add,
                    content: Some("foo".to_string())
                }]
            }],
            taint_flow: None,
        }));
    }

    // test to check the correct generation of a SARIF report with all the default
    // values. This assumes the happy path and does not stress test the
    // code path.
    #[test]
    fn test_generate_sarif_report_happy_path() {
        let rule_single_region = RuleBuilder::default()
            .name("my-rule".to_string())
            .description_base64(Some("YXdlc29tZSBydWxl".to_string()))
            .language(Language::Python)
            .checksum("blabla".to_string())
            .pattern(None)
            .tree_sitter_query_base64(Some("ts-query".to_string()))
            .category(RuleCategory::BestPractices)
            .code_base64("Zm9vYmFyYmF6".to_string())
            .short_description_base64(Some("c2hvcnQgZGVzY3JpcHRpb24=".to_string()))
            .entity_checked(None)
            .rule_type(RuleType::TreeSitterQuery)
            .severity(RuleSeverity::Error)
            .cwe(Some("1234".to_string()))
            .arguments(vec![])
            .tests(vec![])
            .is_testing(false)
            .documentation_url(None)
            .build()
            .unwrap();
        let rule_taint_flow = Rule {
            name: "java-security/flow-rule".to_string(),
            short_description_base64: None,
            description_base64: None,
            category: RuleCategory::Security,
            severity: RuleSeverity::Error,
            language: Language::Java,
            rule_type: RuleType::TreeSitterQuery,
            entity_checked: None,
            code_base64: String::new(),
            cwe: Some("89".to_string()),
            checksum: String::new(),
            pattern: None,
            tree_sitter_query_base64: None,
            arguments: vec![],
            tests: vec![],
            is_testing: false,
            documentation_url: None,
        };
        let region0 = Region {
            start: Position { line: 50, col: 5 },
            end: Position { line: 50, col: 10 },
        };
        let region1 = Region {
            start: Position { line: 40, col: 20 },
            end: Position { line: 40, col: 25 },
        };
        let region2 = Region {
            start: Position { line: 30, col: 12 },
            end: Position { line: 30, col: 17 },
        };
        let violation_taint_flow = Violation {
            start: region0.start,
            end: region0.end,
            message: "flow violation".to_string(),
            severity: RuleSeverity::Error,
            category: RuleCategory::Security,
            fixes: vec![],
            taint_flow: Some(vec![region0, region1, region2]),
        };

        let rule_result_single_region = RuleResultBuilder::default()
            .rule_name("my-rule".to_string())
            .filename("myfile".to_string())
            .violations(vec![ViolationBuilder::default()
                .start(PositionBuilder::default().line(1).col(2).build().unwrap())
                .end(PositionBuilder::default().line(3).col(4).build().unwrap())
                .message("violation message".to_string())
                .severity(RuleSeverity::Error)
                .category(RuleCategory::BestPractices)
                .fixes(vec![RosieFixBuilder::default()
                    .description("myfix".to_string())
                    .edits(vec![EditBuilder::default()
                        .edit_type(EditType::Add)
                        .start(PositionBuilder::default().line(6).col(6).build().unwrap())
                        .end(Some(
                            PositionBuilder::default().line(6).col(6).build().unwrap(),
                        ))
                        .content(Some("newcontent".to_string()))
                        .build()
                        .unwrap()])
                    .build()
                    .unwrap()])
                .taint_flow(None)
                .build()
                .unwrap()])
            .output(None)
            .errors(vec![])
            .execution_time_ms(42)
            .parsing_time_ms(0)
            .query_node_time_ms(0)
            .execution_error(None)
            .build()
            .expect("building violation");
        let rule_result_taint_flow = RuleResult {
            rule_name: "java-security/flow-rule".to_string(),
            filename: "file.java".to_string(),
            violations: vec![violation_taint_flow],
            errors: vec![],
            execution_error: None,
            output: None,
            execution_time_ms: 0,
            parsing_time_ms: 0,
            query_node_time_ms: 0,
        };

        let sarif_report = generate_sarif_report(
            &[rule_single_region.into(), rule_taint_flow.into()],
            &[
                rule_result_single_region.try_into().unwrap(),
                rule_result_taint_flow.try_into().unwrap(),
            ],
            &"mydir".to_string(),
            SarifReportMetadata {
                add_git_info: false,
                debug: false,
                config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                diff_aware_parameters: None,
                execution_time_secs: 42,
            },
            &Default::default(),
        )
        .expect("generate sarif report");

        let sarif_report_to_string = serde_json::to_value(sarif_report).unwrap();
        let expected_json = serde_json::json!(
        {
            "runs":[{
            "artifacts": [
                { "location": { "uri": "myfile" } },
                { "location": { "uri": "file.java" } },
            ],
            "results":[{
                "fixes":[{
                    "artifactChanges":[{
                        "artifactLocation":{"uri":"myfile"},
                        "replacements":[{
                            "deletedRegion":{"endColumn":6,"endLine":6,"startColumn":6,"startLine":6},
                            "insertedContent":{"text":"newcontent"}
                        }]
                    }],
                    "description":{"text":"myfix"}
                }],
                "level":"error",
                "locations":[{
                    "physicalLocation":{
                        "artifactLocation":{"uri":"myfile"},
                        "region":{"endColumn":4,"endLine":3,"startColumn":2,"startLine":1}
                    }
                }],
                "message":{"text":"violation message"},
                "partialFingerprints":{},
                "properties":{"tags":["DATADOG_CATEGORY:BEST_PRACTICES","CWE:1234"]},
                "ruleId":"my-rule","ruleIndex":0
            },{
                "codeFlows": [{
                    "threadFlows":[{
                        "locations": [{
                            "importance": "essential",
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri":"file.java"},
                                    "region": {"startLine":50,"startColumn":5,"endLine":50,"endColumn":10}
                                }
                            }
                        },{
                            "importance": "important",
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri":"file.java"},
                                    "region": {"startLine":40,"startColumn":20,"endLine":40,"endColumn":25}
                                }
                            }
                        },{
                            "importance": "essential",
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri":"file.java"},
                                    "region": {"startLine":30,"startColumn":12,"endLine":30,"endColumn":17}
                                }
                            }
                        }],
                    }]
                }],
                "fixes":[],
                "level":"error",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri":"file.java"},
                        "region": {"startLine":50,"startColumn":5,"endLine":50,"endColumn":10}
                    }
                }],
                "message": {"text":"flow violation"},
                "partialFingerprints": {},
                "properties": {"tags": ["DATADOG_CATEGORY:SECURITY","CWE:89"]},
                "ruleId": "java-security/flow-rule",
                "ruleIndex": 1
            }],
            "tool":{
                "driver":{
                    "informationUri":"https://www.datadoghq.com",
                    "name":"datadog-static-analyzer",
                    "version":CARGO_VERSION,
                    "properties":{
                        "tags":[
                            "DATADOG_DIFF_AWARE_CONFIG_DIGEST:5d7273dec32b80788b4d3eac46c866f0",
                            "DATADOG_EXECUTION_TIME_SECS:42",
                            "DATADOG_DIFF_AWARE_ENABLED:false"
                        ]
                    },
                    "rules":[{
                        "fullDescription":{"text":"awesome rule"},
                        "helpUri":"https://docs.datadoghq.com/static_analysis/rules/my-rule",
                        "id":"my-rule",
                        "properties":{
                            "tags":[
                                "DATADOG_RULE_TYPE:STATIC_ANALYSIS",
                                "CWE:1234"
                            ]},
                        "shortDescription":{"text":"short description"}
                    },{
                        "helpUri":"https://docs.datadoghq.com/static_analysis/rules/java-security/flow-rule",
                        "id":"java-security/flow-rule",
                        "properties":{
                            "tags":[
                                "DATADOG_RULE_TYPE:STATIC_ANALYSIS",
                                "CWE:89"
                            ]
                        },
                    }]
                }
            }}],
            "version":"2.1.0"
        }
                );
        assert_json_eq!(expected_json, sarif_report_to_string);

        // validate the schema
        assert!(validate_data(&sarif_report_to_string));
    }

    // Ensure that diff-aware scanning information are correctly surfaced
    #[test]
    fn test_generate_sarif_diff_aware_scanning() {
        let diff_aware_infos = DiffAwareData {
            base_sha: "d495287772cc8123136b89e8cf5afecbed671823".to_string(),
            files: vec!["path/to/file.py".to_string()],
        };

        let sarif_report = generate_sarif_report(
            &[],
            &vec![],
            &"mydir".to_string(),
            SarifReportMetadata {
                add_git_info: false,
                debug: false,
                config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                diff_aware_parameters: Some(diff_aware_infos),
                execution_time_secs: 42,
            },
            &Default::default(),
        )
        .expect("generate sarif report");

        let sarif_json = serde_json::to_value(sarif_report).unwrap();
        let expected_tags = [
            "DATADOG_DIFF_AWARE_CONFIG_DIGEST:5d7273dec32b80788b4d3eac46c866f0",
            "DATADOG_DIFF_AWARE_ENABLED:true",
            "DATADOG_DIFF_AWARE_BASE_SHA:d495287772cc8123136b89e8cf5afecbed671823",
            "DATADOG_DIFF_AWARE_FILE:path/to/file.py",
        ];

        let actual_tags = sarif_json
            .pointer("/runs/0/tool/driver/properties/tags")
            .unwrap()
            .as_array()
            .unwrap();
        for expected in expected_tags {
            assert!(actual_tags
                .iter()
                .find(|val| val.as_str() == Some(expected))
                .is_some())
        }

        // validate the schema
        assert!(validate_data(&sarif_json));
    }

    /// Tests that artifact URIs are percent-encoded.
    #[test]
    fn test_generate_with_escape_characters() {
        let rule = RuleBuilder::default()
            .name("my-rule".to_string())
            .description_base64(Some("YXdlc29tZSBydWxl".to_string()))
            .language(Language::Python)
            .checksum("blabla".to_string())
            .pattern(None)
            .tree_sitter_query_base64(Some("ts-query".to_string()))
            .category(RuleCategory::BestPractices)
            .code_base64("Zm9vYmFyYmF6".to_string())
            .short_description_base64(Some("c2hvcnQgZGVzY3JpcHRpb24=".to_string()))
            .entity_checked(None)
            .rule_type(RuleType::TreeSitterQuery)
            .severity(RuleSeverity::Error)
            .cwe(Some("1234".to_string()))
            .arguments(vec![])
            .tests(vec![])
            .documentation_url(None)
            .is_testing(false)
            .build()
            .unwrap();

        let rule_result = RuleResultBuilder::default()
            .rule_name("my-rule".to_string())
            .filename("my file/in my directory".to_string())
            .violations(vec![ViolationBuilder::default()
                .start(PositionBuilder::default().line(1).col(2).build().unwrap())
                .end(PositionBuilder::default().line(3).col(4).build().unwrap())
                .message("violation message".to_string())
                .severity(RuleSeverity::Error)
                .category(RuleCategory::BestPractices)
                .fixes(vec![RosieFixBuilder::default()
                    .description("myfix".to_string())
                    .edits(vec![EditBuilder::default()
                        .edit_type(EditType::Add)
                        .start(PositionBuilder::default().line(6).col(6).build().unwrap())
                        .end(Some(
                            PositionBuilder::default().line(6).col(6).build().unwrap(),
                        ))
                        .content(Some("newcontent".to_string()))
                        .build()
                        .unwrap()])
                    .build()
                    .unwrap()])
                .taint_flow(None)
                .build()
                .unwrap()])
            .output(None)
            .errors(vec![])
            .execution_time_ms(42)
            .parsing_time_ms(0)
            .query_node_time_ms(0)
            .execution_error(None)
            .build()
            .expect("building violation");

        let sarif_report = generate_sarif_report(
            &[rule.into()],
            &[rule_result.try_into().unwrap()],
            &"mydir".to_string(),
            SarifReportMetadata {
                add_git_info: false,
                debug: false,
                config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                diff_aware_parameters: None,
                execution_time_secs: 42,
            },
            &Default::default(),
        )
        .expect("generate sarif report");

        let sarif_json = serde_json::to_value(sarif_report).unwrap();
        let expected_subset = serde_json::json!(
        {
          "runs": [
            {
              "results": [
                {
                  "fixes": [
                    {
                      "artifactChanges": [
                        {
                          "artifactLocation": {
                            "uri": "my%20file/in%20my%20directory"
                          },
                        }
                      ],
                    }
                  ],
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": {
                          "uri": "my%20file/in%20my%20directory"
                        },
                      }
                    }
                  ],
                }
              ],
            }
          ],
        }
                );
        assert_json_include!(
            actual: sarif_json,
            expected: expected_subset,
        );

        // validate the schema
        assert!(validate_data(&sarif_json));
    }

    #[test]
    fn test_generate_secret() {
        let rule = secrets::model::secret_rule::SecretRule {
            id: "secret-rule".to_string(),
            name: "secret-rule".to_string(),
            sds_id: "71A7A0ED-DD03-45C5-9C2E-56B30CB566E0".to_string(),
            description: "secret-description".to_string(),
            pattern: "foobarbaz".to_string(),
            priority: RulePriority::Medium,
            default_included_keywords: vec![],
            validators: Some(vec![]),
            match_validation: None,
        };

        #[rustfmt::skip]
        let test_cases = [
            (SecretValidationStatus::NotValidated, "DATADOG_SECRET_VALIDATION_STATUS:NOT_VALIDATED", "warning"),
            (SecretValidationStatus::Valid, "DATADOG_SECRET_VALIDATION_STATUS:VALID", "warning"),
            (SecretValidationStatus::Invalid, "DATADOG_SECRET_VALIDATION_STATUS:INVALID", "warning"),
            (SecretValidationStatus::ValidationError, "DATADOG_SECRET_VALIDATION_STATUS:VALIDATION_ERROR", "warning"),
            (SecretValidationStatus::NotAvailable, "DATADOG_SECRET_VALIDATION_STATUS:NOT_AVAILABLE", "warning"),
        ];

        for case in test_cases {
            let secret_results = vec![SecretResult {
                rule_id: "secret-rule".to_string(),
                rule_name: "secret-rule".to_string(),
                filename: "myfile.py".to_string(),
                message: "some secret".to_string(),
                priority: RulePriority::Medium,
                matches: vec![SecretResultMatch {
                    start: Position { line: 1, col: 1 },
                    end: Position { line: 2, col: 2 },
                    validation_status: case.0,
                }],
            }];

            let sarif_secret_results = secret_results
                .into_iter()
                .map(SarifRuleResult::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)
                .expect("getting results");

            let sarif_report = generate_sarif_report(
                &[rule.clone().into()],
                &sarif_secret_results,
                &"mydir".to_string(),
                SarifReportMetadata {
                    add_git_info: false,
                    debug: false,
                    config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                    diff_aware_parameters: None,
                    execution_time_secs: 42,
                },
                &Default::default(),
            )
            .expect("generate sarif report");

            let expected_subset = serde_json::json!(
            {
              "runs": [
                {
                  "results": [
                    {
                      "fixes": [],
                      "level": case.2,
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": {
                              "uri": "myfile.py"
                            },
                            "region": {
                              "endColumn": 2,
                              "endLine": 2,
                              "startColumn": 1,
                              "startLine": 1
                            }
                          }
                        }
                      ],
                      "message": {
                        "text": "some secret"
                      },
                      "partialFingerprints": {},
                      "properties": {
                        "tags": [
                          "DATADOG_CATEGORY:SECURITY",
                          case.1,
                        ]
                      },
                      "ruleId": "secret-rule",
                      "ruleIndex": 0
                    },
                  ],
                  "tool": {
                    "driver": {
                      "rules": [
                        {
                          "fullDescription": {
                            "text": "secret-description"
                          },
                          "id": "secret-rule",
                          "name": "secret-rule",
                          "properties": {
                            "tags": [
                              "DATADOG_RULE_TYPE:SECRET",
                              "DATADOG_SDS_ID:71A7A0ED-DD03-45C5-9C2E-56B30CB566E0"
                            ]
                          },
                          "shortDescription": {
                            "text": "secret-rule"
                          }
                        }
                      ],
                    }
                  }
                }
              ],
            }
                    );

            let sarif_json = serde_json::to_value(sarif_report).unwrap();
            assert_json_include!(
                actual: sarif_json,
                expected: expected_subset,
            );

            // validate the schema
            assert!(validate_data(&sarif_json));
        }
    }

    #[test]
    fn test_secret_level_uses_rule_severity() {
        // ensure the SARIF level honors the rule's configured severity for all priorities
        let priorities = [
            RulePriority::Info,
            RulePriority::Low,
            RulePriority::Medium,
            RulePriority::High,
            RulePriority::Critical,
        ];

        for priority in priorities {
            let rule = secrets::model::secret_rule::SecretRule {
                id: "secret-rule".to_string(),
                name: "secret-rule".to_string(),
                sds_id: "71A7A0ED-DD03-45C5-9C2E-56B30CB566E0".to_string(),
                description: "secret-description".to_string(),
                pattern: "foobarbaz".to_string(),
                priority,
                default_included_keywords: vec![],
                validators: Some(vec![]),
                match_validation: None,
            };
            let expected_level = get_level_from_severity(map_priority_to_severity(rule.priority));

            let secret_results = vec![SecretResult {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                filename: "myfile.py".to_string(),
                message: "some secret".to_string(),
                priority,
                matches: vec![SecretResultMatch {
                    start: Position { line: 1, col: 1 },
                    end: Position { line: 1, col: 5 },
                    validation_status: SecretValidationStatus::Valid,
                }],
            }];
            let sarif_secret_results = secret_results
                .into_iter()
                .map(SarifRuleResult::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)
                .expect("getting results");

            let sarif_report = generate_sarif_report(
                &[rule.clone().into()],
                &sarif_secret_results,
                &"mydir".to_string(),
                SarifReportMetadata {
                    add_git_info: false,
                    debug: false,
                    config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                    diff_aware_parameters: None,
                    execution_time_secs: 42,
                },
                &Default::default(),
            )
            .expect("generate sarif report");

            let sarif_json = serde_json::to_value(&sarif_report).unwrap();
            let actual_level = sarif_json["runs"][0]["results"][0]["level"]
                .as_str()
                .expect("sarif result should contain a level");
            assert_eq!(
                actual_level, expected_level,
                "priority {:?} should map to {}",
                priority, expected_level
            );
        }
    }

    // in this test, the rule in the violation cannot be found in the list
    // of rules and the rule index in the sarif report must be empty
    #[test]
    fn test_generate_rule_not_found_rule() {
        let rule = RuleBuilder::default()
            .name("my-rule1".to_string())
            .description_base64(Some("YXdlc29tZSBydWxl".to_string()))
            .language(Language::Python)
            .checksum("blabla".to_string())
            .pattern(None)
            .tree_sitter_query_base64(Some("ts-query".to_string()))
            .category(RuleCategory::BestPractices)
            .code_base64("Zm9vYmFyYmF6".to_string())
            .short_description_base64(Some("c2hvcnQgZGVzY3JpcHRpb24=".to_string()))
            .entity_checked(None)
            .rule_type(RuleType::TreeSitterQuery)
            .severity(RuleSeverity::Error)
            .arguments(vec![])
            .cwe(None)
            .tests(vec![])
            .is_testing(false)
            .documentation_url(None)
            .build()
            .unwrap();

        let rule_result = RuleResultBuilder::default()
            .rule_name("my-rule2".to_string())
            .filename("myfile".to_string())
            .violations(vec![ViolationBuilder::default()
                .start(PositionBuilder::default().line(1).col(2).build().unwrap())
                .end(PositionBuilder::default().line(3).col(4).build().unwrap())
                .message("violation message".to_string())
                .severity(RuleSeverity::Error)
                .category(RuleCategory::BestPractices)
                .fixes(vec![RosieFixBuilder::default()
                    .description("myfix".to_string())
                    .edits(vec![EditBuilder::default()
                        .edit_type(EditType::Add)
                        .start(PositionBuilder::default().line(6).col(6).build().unwrap())
                        .end(Some(
                            PositionBuilder::default().line(6).col(6).build().unwrap(),
                        ))
                        .content(Some("newcontent".to_string()))
                        .build()
                        .unwrap()])
                    .build()
                    .unwrap()])
                .taint_flow(None)
                .build()
                .unwrap()])
            .output(None)
            .errors(vec![])
            .execution_time_ms(42)
            .execution_error(None)
            .parsing_time_ms(0)
            .query_node_time_ms(0)
            .build()
            .expect("building violation");

        let sarif_report = generate_sarif_report(
            &[rule.into()],
            &[rule_result.try_into().unwrap()],
            &"mydir".to_string(),
            SarifReportMetadata {
                add_git_info: false,
                debug: false,
                config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                diff_aware_parameters: None,
                execution_time_secs: 42,
            },
            &Default::default(),
        )
        .expect("generate sarif report");
        assert!(sarif_report
            .runs
            .get(0)
            .unwrap()
            .results
            .as_ref()
            .unwrap()
            .get(0)
            .unwrap()
            .rule_index
            .is_none());
        // validate the schema
        assert!(validate_data(&serde_json::to_value(sarif_report).unwrap()));
    }

    /// Tests that `generate_sarif_report` only includes unique artifacts, regardless of how many
    /// times they appear across results.
    #[test]
    fn generate_sarif_report_artifacts_no_dups() {
        let violation_paths = ["src/zzzzzz.py", "src/yyyyyy.py", "src/zzzzzz.py"];
        let rule_results = violation_paths
            .into_iter()
            .enumerate()
            .map(|(idx, file_path)| {
                let violation = Violation {
                    start: Position::new((idx + 1) as u32, 1),
                    end: Position::new((idx + 1) as u32, 10),
                    message: "violation message".to_string(),
                    severity: RuleSeverity::Error,
                    category: RuleCategory::BestPractices,
                    fixes: vec![],
                    taint_flow: None,
                };
                let rr = RuleResult {
                    rule_name: format!("rule-{idx}"),
                    filename: file_path.to_string(),
                    violations: vec![violation],
                    errors: vec![],
                    execution_error: None,
                    output: None,
                    execution_time_ms: 0,
                    parsing_time_ms: 0,
                    query_node_time_ms: 0,
                };
                SarifRuleResult::try_from(rr).unwrap()
            })
            .collect::<Vec<_>>();

        let sarif_report = generate_sarif_report(
            // Unnecessary for this test
            &[],
            &rule_results,
            // Unnecessary for this test
            &"src/dir".to_string(),
            // Unnecessary for this test
            SarifReportMetadata {
                add_git_info: false,
                debug: false,
                config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                diff_aware_parameters: None,
                execution_time_secs: 42,
            },
            &Default::default(),
        )
        .unwrap();

        let sarif_json = serde_json::to_value(sarif_report).unwrap();

        let actual_result_locs = (0..violation_paths.len())
            .map(|idx| {
                let pointer = format!(
                    "/runs/0/results/{idx}/locations/0/physicalLocation/artifactLocation/uri"
                );
                sarif_json.pointer(&pointer).unwrap().as_str().unwrap()
            })
            .collect::<Vec<_>>();
        let actual_artifact_locs = {
            let artifact_count = sarif_json
                .pointer("/runs/0/artifacts")
                .unwrap()
                .as_array()
                .unwrap()
                .len();
            (0..artifact_count)
                .map(|idx| {
                    let pointer = format!("/runs/0/artifacts/{idx}/location/uri");
                    sarif_json.pointer(&pointer).unwrap().as_str().unwrap()
                })
                .collect::<Vec<_>>()
        };

        assert_eq!(actual_result_locs, violation_paths);
        assert_eq!(actual_artifact_locs, vec!["src/zzzzzz.py", "src/yyyyyy.py"])
    }

    /// Tests that `generate_sarif_report` adds a tag for artifacts that are classified as test files,
    /// and no tags for those that aren't.
    #[test]
    fn generate_sarif_report_artifact_test_file_tag() {
        fn has_tag(list: &[serde_json::Value], tag: &str) -> bool {
            list.iter().any(|v| v.as_str() == Some(tag))
        }
        const TEST_FILE_PATH: &str = "src/file-a-test-file.py";
        const NON_TEST_FILE_PATH: &str = "src/file-b-not-test-file.py";

        let path_metadata = HashMap::from([(
            TEST_FILE_PATH.to_string(),
            #[allow(clippy::needless_update)]
            ArtifactClassification {
                is_test_file: true,
                ..Default::default()
            },
        )]);
        // Test invariant
        assert!(!path_metadata.contains_key(NON_TEST_FILE_PATH));

        let violation = Violation {
            start: Position::new(1, 1),
            end: Position::new(1, 10),
            message: "violation message".to_string(),
            severity: RuleSeverity::Error,
            category: RuleCategory::BestPractices,
            fixes: vec![],
            taint_flow: None,
        };
        let rule_results = [TEST_FILE_PATH, NON_TEST_FILE_PATH]
            .into_iter()
            .map(|path| {
                let rr: SarifRuleResult = RuleResult {
                    rule_name: "ruleset/rule-name".to_string(),
                    filename: path.to_string(),
                    violations: vec![violation.clone()],
                    errors: vec![],
                    execution_error: None,
                    output: None,
                    execution_time_ms: 0,
                    parsing_time_ms: 0,
                    query_node_time_ms: 0,
                }
                .try_into()
                .unwrap();
                rr
            })
            .collect::<Vec<_>>();

        let sarif_report = generate_sarif_report(
            // Unnecessary for this test
            &[],
            &rule_results,
            // Unnecessary for this test
            &"src/dir".to_string(),
            // Unnecessary for this test
            SarifReportMetadata {
                add_git_info: false,
                debug: false,
                config_digest: "5d7273dec32b80788b4d3eac46c866f0".to_string(),
                diff_aware_parameters: None,
                execution_time_secs: 42,
            },
            &path_metadata,
        )
        .unwrap();

        let sarif_json = serde_json::to_value(sarif_report).unwrap();
        let artifact_tags = (0..2)
            .map(|idx| {
                let artifact_pointer = format!("/runs/0/artifacts/{idx}");
                let artifact = sarif_json.pointer(&artifact_pointer).unwrap();
                let tags = artifact
                    .get("properties")
                    .and_then(|obj| {
                        obj.get("tags")
                            .unwrap()
                            .as_array()
                            .map(|arr| arr.as_slice())
                    })
                    .unwrap_or(&[]);
                let uri_pointer = format!("/runs/0/artifacts/{idx}/location/uri");
                let uri = sarif_json.pointer(&uri_pointer).unwrap().as_str().unwrap();
                (uri, tags)
            })
            .collect::<Vec<_>>();
        assert!(
            artifact_tags[0].0 == TEST_FILE_PATH
                && has_tag(artifact_tags[0].1, CLASSIFICATION_TEST_FILE)
        );
        assert!(
            artifact_tags[1].0 == NON_TEST_FILE_PATH
                && !has_tag(artifact_tags[1].1, CLASSIFICATION_TEST_FILE)
        );
    }
}
