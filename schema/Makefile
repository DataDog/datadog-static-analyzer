all: test

test: test-v1.0-schema-valid test-v1.0-schema-invalid test-legacy-valid test-legacy-invalid

test-v1.0-schema-valid:
	npx --yes ajv-cli@5.0.0 test --spec=draft2020 -s sast/v1.0/validation.schema.json -r sast/v1.0/schema.json -d "tests/v1.0/valid/*.yml" --valid

test-v1.0-schema-invalid:
	npx --yes ajv-cli@5.0.0 test --spec=draft2020 -s sast/v1.0/validation.schema.json -r sast/v1.0/schema.json -d "tests/v1.0/invalid/*.yml" --invalid

test-legacy-valid:
	npx --yes ajv-cli@5.0.0 test -s legacy/schema.json -d "legacy/examples/valid/*.yml" --valid

test-legacy-invalid:
	npx --yes ajv-cli@5.0.0 test -s legacy/schema.json -d "legacy/examples/invalid/*.yml" --invalid

.PHONY: test test-v1.0-schema-valid test-v1.0-schema-invalid test-legacy-valid test-legacy-invalid
