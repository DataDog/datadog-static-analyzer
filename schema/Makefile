all: test

test: test-schema-valid test-schema-invalid test-v1-valid test-v1-invalid test-v2-valid test-v2-invalid

examples-valid = $(1)/examples/valid/*.yml
examples-invalid = $(1)/examples/invalid/*.yml

test-schema-valid:
	npx --yes ajv-cli@5.0.0 test -s schema.json -r v1/schema.json -d "$(call examples-valid,v1)" --valid

test-schema-invalid:
	npx --yes ajv-cli@5.0.0 test -s schema.json -r v1/schema.json -d "$(call examples-invalid,v1)" --invalid

test-v1-valid:
	npx --yes ajv-cli@5.0.0 test -s v1/schema.json -d "$(call examples-valid,v1)" --valid

test-v1-invalid:
	npx --yes ajv-cli@5.0.0 test -s v1/schema.json -d "$(call examples-invalid,v1)" --invalid

test-v2-valid:
	npx --yes ajv-cli@5.0.0 test -s v2/schema.json -d "$(call examples-valid,v2)" --valid

test-v2-invalid:
	npx --yes ajv-cli@5.0.0 test -s v2/schema.json -d "$(call examples-invalid,v2)" --invalid

.PHONY: test test-schema-valid test-schema-invalid test-v1-valid test-v1-invalid test-v2-valid test-v2-invalid
