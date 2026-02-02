## How to release a new version?

### Step 1: compute the new version

Read the prompt, extract the version from `Cargo.toml` and add a new minor version. Always increment
the version but never have a 10 version.


**Examples**

The new version should be a minor version:
 - if the current version is `0.7.4` the new version is `0.7.5`
 - if the current version is `0.7.9` the new version is `0.8.0`

## Step 2: Update the version

Edit `Cargo.toml` and replace the version

```toml
[workspace.package]
version = "X.Y.Z"
```

### Step 3: lock dependencies

Run `cargo check`

### Step 4: Update `versions.json`

Open `versions.json` and update the file with the new versions, adding the appropriate links for the 
new version. The file should have something like this.

```json
  "X.Y.Z": {
    "cli": {
      "windows": {
        "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-x86_64-pc-windows-msvc.zip"
      },
      "linux": {
        "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-x86_64-unknown-linux-gnu.zip",
        "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-aarch64-unknown-linux-gnu.zip"
      },
      "macos": {
        "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-x86_64-apple-darwin.zip",
        "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-aarch64-apple-darwin.zip"
      }
    },
    "server": {
      "windows": {
        "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-server-x86_64-pc-windows-msvc.zip"
      },
      "linux": {
        "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-server-x86_64-unknown-linux-gnu.zip",
        "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-server-aarch64-unknown-linux-gnu.zip"
      },
      "macos": {
        "x86_64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-server-x86_64-apple-darwin.zip",
        "aarch64": "https://github.com/DataDog/datadog-static-analyzer/releases/download/X.Y.Z/datadog-static-analyzer-server-aarch64-apple-darwin.zip"
      }
    }
  },
```

### Commit your changes

First, create a new branch `<$USERNAME>/version-X.Y.Z`

```bash
git checkout -b "$USER/version-X.Y.Z"
```

Then, commit your changes with a message that contains the new version number

```bash
git commit -m 'release version X.Y.Z'
```