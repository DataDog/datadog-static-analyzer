
## Build the project

You need to have all the necessary [tree-sitter](https://github.com/tree-sitter) repositories
in `kernel` for the analysis to work. The `build` process will take care of this for you:

```shell
cargo build
```


## Analyze a directory

```shell

cargo run --bin datadog-static-analyzer -- --directory <SOURCE> --output result.json --format sarif --debug yes
```

## Start a local server

```shell
cargo run --bin datadog-static-analyzer-server -- --port <server-port> -a <server-address>
```

## Run tests

Run all tests

```shell
cargo test
```


## Test a ruleset

```shell
cargo run --bin datadog-static-analyzer-test-ruleset -- -r <ruleset-name>1
```


## Run tests with output

```shell
cargo test -- --nocapture
```


## Test a request to the server

First, start the server using

```shell
cargo run --bin datadog-static-analyzer-server
```


### Get an analysis request
```shell

curl -X POST \
     -H "Content-Type: application/json" \
     --data '{
        "filename": "myfile.py",
        "file_encoding": "utf-8",
        "language": "PYTHON",
        "code": "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M=",
        "rules": [
          {
              "id": "myrule",
              "short_description": "",
              "description": "",
              "language": "PYTHON",
              "type": "TREE_SITTER_QUERY",
              "entity_checked": null,
              "code": "ZnVuY3Rpb24gdmlzaXQobm9kZSwgZmlsZW5hbWUsIGNvZGUpIHsKICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9IG5vZGUuY2FwdHVyZXNbIm5hbWUiXTsKICAgIGlmKGZ1bmN0aW9uTmFtZSkgewogICAgICAgIGNvbnN0IGVycm9yID0gYnVpbGRFcnJvcihmdW5jdGlvbk5hbWUuc3RhcnQubGluZSwgZnVuY3Rpb25OYW1lLnN0YXJ0LmNvbCwgZnVuY3Rpb25OYW1lLmVuZC5saW5lLCBmdW5jdGlvbk5hbWUuZW5kLmNvbCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImludmFsaWQgbmFtZSIsICJDUklUSUNBTCIsICJzZWN1cml0eSIpOwoKICAgICAgICBjb25zdCBlZGl0ID0gYnVpbGRFZGl0KGZ1bmN0aW9uTmFtZS5zdGFydC5saW5lLCBmdW5jdGlvbk5hbWUuc3RhcnQuY29sLCBmdW5jdGlvbk5hbWUuZW5kLmxpbmUsIGZ1bmN0aW9uTmFtZS5lbmQuY29sLCAidXBkYXRlIiwgImJhciIpOwogICAgICAgIGNvbnN0IGZpeCA9IGJ1aWxkRml4KCJ1c2UgYmFyIiwgW2VkaXRdKTsKICAgICAgICBhZGRFcnJvcihlcnJvci5hZGRGaXgoZml4KSk7CiAgICB9Cn0=",
              "tree_sitter_query": "KGZ1bmN0aW9uX2RlZmluaXRpb24KICAgIG5hbWU6IChpZGVudGlmaWVyKSBAbmFtZQogIHBhcmFtZXRlcnM6IChwYXJhbWV0ZXJzKSBAcGFyYW1zCik="
          }
        ]
     }' \
     http://localhost:8000/analyze
```

### Get the AST Tree

```shell
curl -X POST \
-H "Content-Type: application/json" \
--data '{
"file_encoding": "utf-8",
"language": "PYTHON",
"code": "ZGVmIGZvbyhhcmcxKToKICAgIHBhc3M="
}' \
http://localhost:8000/get-treesitter-ast
```
