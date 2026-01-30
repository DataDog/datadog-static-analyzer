all: test

test: test-valid test-invalid

INVALID_FILES=examples/invalid/*.yml
VALID_FILES=examples/valid/*.yml

test-valid:
	npx --yes ajv-cli@5.0.0 test -s schema.json -d "${VALID_FILES}" --valid

test-invalid:
	npx --yes ajv-cli@5.0.0 test -s schema.json -d "${INVALID_FILES}" --invalid

.PHONY: test test-valid test-invalid
