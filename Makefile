.PHONY: validate lint test setup scan help

WORKFLOW := .github/workflows/reusable-security-pipeline.yml

help:
	@echo "validate  check workflow YAML is parseable"
	@echo "lint      run yamllint on the workflow file"
	@echo "test      validate + lint"
	@echo "setup     run setup.sh interactively"

validate:
	@python3 -c "import yaml; yaml.safe_load(open('$(WORKFLOW)'))" && echo "YAML valid: $(WORKFLOW)"

lint:
	@command -v yamllint > /dev/null 2>&1 || pip install yamllint -q
	yamllint -d '{extends: relaxed, rules: {line-length: {max: 200}}}' $(WORKFLOW)

test: validate lint

setup:
	@bash setup.sh

scan:
	./securepipe scan --target ./sample-apps/python
