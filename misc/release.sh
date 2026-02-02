#!/bin/bash

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Datadog Static Analyzer Release Script ===${NC}\n"

# Step 1: Get current version from Cargo.toml
echo -e "${YELLOW}Step 1: Reading current version from Cargo.toml${NC}"
CURRENT_VERSION=$(grep -A 1 '\[workspace.package\]' Cargo.toml | grep 'version' | sed 's/.*"\(.*\)".*/\1/')
echo "Current version: $CURRENT_VERSION"

# Parse version components
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# Calculate new version
if [ "$PATCH" -eq 9 ]; then
    NEW_MINOR=$((MINOR + 1))
    NEW_PATCH=0
else
    NEW_MINOR=$MINOR
    NEW_PATCH=$((PATCH + 1))
fi

NEW_VERSION="${MAJOR}.${NEW_MINOR}.${NEW_PATCH}"
echo -e "${GREEN}New version: $NEW_VERSION${NC}\n"

# Step 2: Update version in Cargo.toml
echo -e "${YELLOW}Step 2: Updating Cargo.toml${NC}"
sed -i.bak "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
rm Cargo.toml.bak
echo -e "${GREEN}Updated Cargo.toml${NC}\n"

# Step 3: Lock dependencies
echo -e "${YELLOW}Step 3: Running cargo check to lock dependencies${NC}"
cargo check
echo -e "${GREEN}Dependencies locked${NC}\n"

# Step 4: Update versions.json
echo -e "${YELLOW}Step 4: Updating versions.json${NC}"

# Create the new version entry
NEW_ENTRY=$(cat <<EOF
      "$NEW_VERSION": {
        "cli": {
          "windows": {
            "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-x86_64-pc-windows-msvc.zip"
          },
          "linux": {
            "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-x86_64-unknown-linux-gnu.zip",
            "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-aarch64-unknown-linux-gnu.zip"
          },
          "macos": {
            "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-x86_64-apple-darwin.zip",
            "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-aarch64-apple-darwin.zip"
          }
        },
        "server": {
          "windows": {
            "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-server-x86_64-pc-windows-msvc.zip"
          },
          "linux": {
            "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-server-x86_64-unknown-linux-gnu.zip",
            "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-server-aarch64-unknown-linux-gnu.zip"
          },
          "macos": {
            "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-server-x86_64-apple-darwin.zip",
            "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/$NEW_VERSION/datadog-static-analyzer-server-aarch64-apple-darwin.zip"
          }
        }
      },
EOF
)

# Insert the new entry after the line containing "0": {
# Write the new entry to a temporary file
TEMP_FILE=$(mktemp)
echo "$NEW_ENTRY" > "$TEMP_FILE"

# Use sed to read and insert the temp file content after the line containing "0": {
sed -i.bak "/\"$MAJOR\": {/r $TEMP_FILE" versions.json
rm versions.json.bak "$TEMP_FILE"

echo -e "${GREEN}Updated versions.json${NC}\n"

# Step 5: Create new branch
echo -e "${YELLOW}Step 5: Creating new branch${NC}"
BRANCH_NAME="$USER/version-$NEW_VERSION"
git checkout -b "$BRANCH_NAME"
echo -e "${GREEN}Created branch: $BRANCH_NAME${NC}\n"

# Step 6: Stage and commit changes
echo -e "${YELLOW}Step 6: Committing changes${NC}"
git add Cargo.toml Cargo.lock versions.json
git commit -m "release version $NEW_VERSION"
echo -e "${GREEN}Committed changes${NC}\n"

echo -e "${BLUE}=== Release preparation complete! ===${NC}"
echo -e "${GREEN}New version: $NEW_VERSION${NC}"
echo -e "${GREEN}Branch: $BRANCH_NAME${NC}"
echo ""
echo "Next steps:"
echo "1. Push the branch: git push -u origin $BRANCH_NAME"
echo "2. Create a pull request"
echo "3. After merge, create a GitHub release with tag $NEW_VERSION"
