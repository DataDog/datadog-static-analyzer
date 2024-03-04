all: test

test: test-valid test-invalid

INVALID_FILES=examples/invalid/*.yml
VALID_FILES=examples/valid/*.yml

test-valid:
	pajv test -s schema.json -d "${VALID_FILES}" --valid

test-invalid:
	pajv test -s schema.json -d "${INVALID_FILES}" --invalid

.PHONY: test test-valid test-invalid
