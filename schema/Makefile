all: test

test: test-schema-valid test-schema-invalid test-legacy-valid test-legacy-invalid test-v2-valid test-v2-invalid

examples-valid = $(1)/examples/valid/*.yml
examples-invalid = $(1)/examples/invalid/*.yml

test-schema-valid:
	npx --yes ajv-cli@5.0.0 test -s schema.json -r legacy/schema.json -d "$(call examples-valid,legacy)" --valid

test-schema-invalid:
	npx --yes ajv-cli@5.0.0 test -s schema.json -r legacy/schema.json -d "$(call examples-invalid,legacy)" --invalid

test-legacy-valid:
	npx --yes ajv-cli@5.0.0 test -s legacy/schema.json -d "$(call examples-valid,legacy)" --valid

test-legacy-invalid:
	npx --yes ajv-cli@5.0.0 test -s legacy/schema.json -d "$(call examples-invalid,legacy)" --invalid

test-v2-valid:
	npx --yes ajv-cli@5.0.0 test -s v2/schema.json -d "$(call examples-valid,v2)" --valid

test-v2-invalid:
	npx --yes ajv-cli@5.0.0 test -s v2/schema.json -d "$(call examples-invalid,v2)" --invalid

.PHONY: test test-schema-valid test-schema-invalid test-legacy-valid test-legacy-invalid test-v2-valid test-v2-invalid
