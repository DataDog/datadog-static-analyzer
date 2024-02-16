# vectorscan-sys

Low-level bindings to [Vectorscan](https://github.com/VectorCamp/vectorscan), a fork
of [Hyperscan](https://github.com/intel/hyperscan), a high-performance multiple regex matching library.

Currently, only static linking is supported.

---

# Build Instructions
### Debian/Ubuntu
Install required dependencies:
```shell
sudo apt install build-essential cmake ragel
```

### macOS - arm64
First, install Xcode Command Line Tools, and then install required dependencies:

**Homebrew**
```shell
brew install boost cmake ragel
```
