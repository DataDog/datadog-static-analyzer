#!/bin/sh -l

# NOTE:
# This file is invoked by datadog-static-analyzer-github-action@v1 and v2. These actions are
# no longer supported. Any proposed changes to the logic below should be added instead to the
# action steps in datadog-static-analyzer-github-action@v3.

echo "::warning title=Unsupported Action Version::datadog-static-analyzer-github-action@v1 and v2 are unsupported.%0A%0AConsider upgrading to v3.%0A%0ASee: https://github.com/DataDog/datadog-static-analyzer-github-action/releases/tag/v3.0.0"

########################################################
# Check variables
########################################################
if [ -z "$DD_API_KEY" ]; then
	echo "DD_API_KEY not set. Please set one and try again."
	exit 1
fi

if [ -z "$DD_APP_KEY" ]; then
	echo "DD_APP_KEY not set. Please set one and try again."
	exit 1
fi

if [ -n "$DD_ENV" ]; then
	echo "::warning title=Deprecated environment variable::DD_ENV has been set, but it is no longer functional. This warning will be removed in a future update."
fi

if [ -n "$DD_SERVICE" ]; then
	echo "::warning title=Deprecated environment variable::DD_SERVICE has been set, but it is no longer functional. This warning will be removed in a future update."
fi

if [ -z "$CPU_COUNT" ]; then
	# the default CPU count is 2
	CPU_COUNT=2
fi

if [ "$ENABLE_PERFORMANCE_STATISTICS" = "true" ]; then
	ENABLE_PERFORMANCE_STATISTICS="--performance-statistics"
else
	ENABLE_PERFORMANCE_STATISTICS=""
fi

if [ "$ENABLE_DEBUG" = "yes" ]; then
	DEBUG_ARGUMENT_VALUE="yes"
else
	DEBUG_ARGUMENT_VALUE="no"
fi

if [ -n "$SUBDIRECTORY" ]; then
	for subdirectory in $SUBDIRECTORY; do
		SUBDIRECTORY_OPTION="$SUBDIRECTORY_OPTION --subdirectory $subdirectory"
	done
fi

if [ "$DIFF_AWARE" = "true" ]; then
	DIFF_AWARE_VALUE="--diff-aware"
else
	DIFF_AWARE_VALUE=""
fi

if [ "$SECRETS_ENABLED" = "true" ]; then
	SECRETS_ENABLED_VALUE="--enable-secrets true"
else
	SECRETS_ENABLED_VALUE=""
fi

if [ "$STATIC_ANALYSIS_ENABLED" = "false" ]; then
	STATIC_ANALYSIS_ENABLED_VALUE="--enable-static-analysis false"
else
	STATIC_ANALYSIS_ENABLED_VALUE="--enable-static-analysis true"
fi

########################################################
# Output directory
########################################################
echo "Getting output directory"
OUTPUT_DIRECTORY=$(mktemp -d)

# Check that datadog-ci was installed
if [ ! -d "$OUTPUT_DIRECTORY" ]; then
	echo "Output directory ${OUTPUT_DIRECTORY} does not exist"
	exit 1
fi

OUTPUT_FILE="$OUTPUT_DIRECTORY/output.sarif"

echo "Done: will output results at $OUTPUT_FILE"

########################################################
# Execute the tool and upload results
########################################################

# Navigate to workspace root, so the datadog-ci command can access the git info
cd $GITHUB_WORKSPACE || exit 1
git config --global --add safe.directory $GITHUB_WORKSPACE || exit 1

# Only upload git metadata if diff aware is enabled.
if [ "$DIFF_AWARE" = "true" ]; then
	echo "Disabling extensions.worktreeConfig"
	git config --unset extensions.worktreeConfig
	echo "Done"

	echo "Upload git metadata"
	datadog-ci git-metadata upload
	echo "Done"
fi

echo "Starting Static Analysis"
datadog-static-analyzer -i "$GITHUB_WORKSPACE" -g -o "$OUTPUT_FILE" -f sarif --cpus "$CPU_COUNT" "$ENABLE_PERFORMANCE_STATISTICS" --debug $DEBUG_ARGUMENT_VALUE $SUBDIRECTORY_OPTION $DIFF_AWARE_VALUE $SECRETS_ENABLED_VALUE $STATIC_ANALYSIS_ENABLED_VALUE || exit 1
echo "Done"

echo "Uploading Static Analysis Results to Datadog"
datadog-ci sarif upload "$OUTPUT_FILE" --service datadog-static-analyzer --env ci || exit 1
echo "Done"
