## What this changes

<!-- One paragraph. What does the pipeline do differently after this PR? -->

## Why

<!-- Link the issue or describe the problem being solved. -->

## Checklist

- [ ] YAML validates: `make validate` passes with no errors
- [ ] Every new job has a `name:` field
- [ ] Every new step has a `name:` field
- [ ] All scanner runs have `|| true` so findings do not skip SARIF upload
- [ ] All SARIF upload steps have `if: always()`
- [ ] No hardcoded values — everything goes through inputs
- [ ] Tested end to end against a real caller workflow (not just YAML lint)
- [ ] Docs updated if inputs, outputs, or behaviour changed

## Test run

<!-- Paste the URL of a passing Actions run that validates this change. -->
