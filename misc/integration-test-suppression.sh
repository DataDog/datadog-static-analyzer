#!/bin/bash

cargo fetch
cargo build --locked --profile release-dev --bin datadog-static-analyzer

WORK_DIR=$(mktemp -d)

# Create a Python file with two violations:
#   - line 3: suppressed with no-dd-sa
#   - line 5: not suppressed
cat > "${WORK_DIR}/test.py" <<'EOF'
import os

# no-dd-sa
os.system(f'mv {saved_file_path} {public_upload_file_path}')

os.system(f'mv {saved_file_path} {do_something()}')
EOF

cat > "${WORK_DIR}/code-security.datadog.yaml" <<'EOF'
schema-version: v1.0
sast:
  use-default-rulesets: false
  use-rulesets:
    - python-security
EOF

ANALYZER="./target/release-dev/datadog-static-analyzer"
SARIF_OUTPUT="${WORK_DIR}/results.sarif"
CSV_OUTPUT="${WORK_DIR}/results.csv"

# ── SARIF export ──────────────────────────────────────────────────────────────

"${ANALYZER}" --directory "${WORK_DIR}" -o "${SARIF_OUTPUT}" -f sarif
if [ $? -ne 0 ]; then
  echo "FAIL: analyzer exited with non-zero status during SARIF export"
  exit 1
fi

# Suppressed finding must appear in SARIF with a suppressions property
suppressed_in_sarif=$(jq '[.runs[0].results[] | select(.suppressions != null and (.suppressions | length) > 0)] | length' "${SARIF_OUTPUT}")
if [ "${suppressed_in_sarif}" -lt 1 ]; then
  echo "FAIL: expected at least one suppressed result in SARIF (with suppressions property), got ${suppressed_in_sarif}"
  exit 1
fi
echo "PASS: suppressed finding is present in SARIF with suppressions property"

# Non-suppressed finding must appear in SARIF without a suppressions property
nonsuppressed_in_sarif=$(jq '[.runs[0].results[] | select(.suppressions == null or (.suppressions | length) == 0)] | length' "${SARIF_OUTPUT}")
if [ "${nonsuppressed_in_sarif}" -lt 1 ]; then
  echo "FAIL: expected at least one non-suppressed result in SARIF (without suppressions property), got ${nonsuppressed_in_sarif}"
  exit 1
fi
echo "PASS: non-suppressed finding is present in SARIF without suppressions property"

# ── CSV export ────────────────────────────────────────────────────────────────

"${ANALYZER}" --directory "${WORK_DIR}" -o "${CSV_OUTPUT}" -f csv
if [ $? -ne 0 ]; then
  echo "FAIL: analyzer exited with non-zero status during CSV export"
  exit 1
fi

# The suppressed violation is on line 4 of test.py; it must NOT appear in the CSV
suppressed_in_csv=$(awk -F',' '$6 == "4"' "${CSV_OUTPUT}" | wc -l | tr -d ' ')
if [ "${suppressed_in_csv}" -ne 0 ]; then
  echo "FAIL: suppressed finding (line 4) should not appear in CSV, but found ${suppressed_in_csv} row(s)"
  exit 1
fi
echo "PASS: suppressed finding is absent from CSV"

# The non-suppressed violation is on line 6 of test.py; it must appear in the CSV
nonsuppressed_in_csv=$(awk -F',' '$6 == "6"' "${CSV_OUTPUT}" | wc -l | tr -d ' ')
if [ "${nonsuppressed_in_csv}" -lt 1 ]; then
  echo "FAIL: non-suppressed finding (line 6) should appear in CSV, but found ${nonsuppressed_in_csv} row(s)"
  exit 1
fi
echo "PASS: non-suppressed finding is present in CSV"

# ── --fail-on-any-violation respects suppressions ────────────────────────────

# Run with only the suppressed severity: should exit 0 (no unsuppressed violations of that kind)
SUPPRESSED_ONLY_OUTPUT="${WORK_DIR}/results-suppressed-only.sarif"

# First, discover the severity of the suppressed violation from the SARIF output
suppressed_severity=$(jq -r '[.runs[0].results[] | select(.suppressions != null and (.suppressions | length) > 0)] | .[0].level' "${SARIF_OUTPUT}")

# Create a file that has ONLY the suppressed violation (rename the non-suppressed line)
cat > "${WORK_DIR}/test_only_suppressed.py" <<'EOF'
import os

# no-dd-sa
os.system(f'mv {saved_file_path} {public_upload_file_path}')
EOF

SUPPRESSED_ONLY_DIR=$(mktemp -d)
cp "${WORK_DIR}/test_only_suppressed.py" "${SUPPRESSED_ONLY_DIR}/test.py"
cp "${WORK_DIR}/code-security.datadog.yaml" "${SUPPRESSED_ONLY_DIR}/"

"${ANALYZER}" --directory "${SUPPRESSED_ONLY_DIR}" -o "${SUPPRESSED_ONLY_DIR}/results.sarif" -f sarif \
  --fail-on-any-violation=error,warning,notice,none
if [ $? -ne 0 ]; then
  echo "FAIL: --fail-on-any-violation should not trigger when all violations are suppressed"
  exit 1
fi
echo "PASS: --fail-on-any-violation exits 0 when all violations are suppressed"

# Run with the non-suppressed file: should exit non-zero
NON_SUPPRESSED_DIR=$(mktemp -d)
cat > "${NON_SUPPRESSED_DIR}/test.py" <<'EOF'
import os

os.system(f'mv {saved_file_path} {do_something()}')
EOF
cp "${WORK_DIR}/code-security.datadog.yaml" "${NON_SUPPRESSED_DIR}/"

"${ANALYZER}" --directory "${NON_SUPPRESSED_DIR}" -o "${NON_SUPPRESSED_DIR}/results.sarif" -f sarif \
  --fail-on-any-violation=error,warning,notice,none
if [ $? -eq 0 ]; then
  echo "FAIL: --fail-on-any-violation should trigger when there are non-suppressed violations"
  exit 1
fi
echo "PASS: --fail-on-any-violation exits non-zero when there are non-suppressed violations"

# ── Secrets: SARIF suppression ────────────────────────────────────────────────

SECRETS_DIR=$(mktemp -d)
cp "${WORK_DIR}/code-security.datadog.yaml" "${SECRETS_DIR}/"

cat > "${SECRETS_DIR}/secrets-test.sh" <<'EOF'
export DD_SITE=datad0g.com
export DD_APP_KEY=woiejfwoeij
#no-dd-secrets
export DD_API_KEY=2ad38d7abc128d87720af72f1eb7b174
EOF

SECRETS_SARIF="${SECRETS_DIR}/results.sarif"

"${ANALYZER}" --directory "${SECRETS_DIR}" -o "${SECRETS_SARIF}" -f sarif --enable-secrets true
if [ $? -ne 0 ]; then
  echo "FAIL: analyzer exited with non-zero status during secrets SARIF export"
  exit 1
fi

# DD_API_KEY on line 4 must appear in SARIF with a suppressions property
suppressed_secret=$(jq '[.runs[0].results[] | select(.suppressions != null and (.suppressions | length) > 0) | select(.locations[0].physicalLocation.region.startLine == 4)] | length' "${SECRETS_SARIF}")
if [ "${suppressed_secret}" -lt 1 ]; then
  echo "FAIL: expected suppressed secret on line 4 to appear in SARIF with suppressions property, got ${suppressed_secret}"
  exit 1
fi
echo "PASS: suppressed secret (line 4) is present in SARIF with suppressions property"

# DD_API_KEY on line 4 must NOT appear as a non-suppressed result
unsuppressed_secret_line4=$(jq '[.runs[0].results[] | select(.suppressions == null or (.suppressions | length) == 0) | select(.locations[0].physicalLocation.region.startLine == 4)] | length' "${SECRETS_SARIF}")
if [ "${unsuppressed_secret_line4}" -ne 0 ]; then
  echo "FAIL: suppressed secret on line 4 should not appear as non-suppressed in SARIF, got ${unsuppressed_secret_line4}"
  exit 1
fi
echo "PASS: suppressed secret (line 4) does not appear as non-suppressed in SARIF"

echo "All tests passed"
exit 0
