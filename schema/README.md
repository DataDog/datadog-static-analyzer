# Schema for datadog-static-analyzer

1. It validates what objects are required and valid
2. Adding more properties in the schema is still making them valid
3. Some validation may be missing but the core idea is present

## How to test

1. Install https://www.npmjs.com/package/pajv (`npm install -g pajv`)
2. Invoke `make`


## Configuration file examples

 - [valid files here](examples/valid)
 - [invalid files here](examples/invalid)
