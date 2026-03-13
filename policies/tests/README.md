# Policy Test Fixtures

This directory contains versioned test fixtures for OPA/Conftest policies.

Fixtures are used for policy regression testing and coverage enforcement.

## Structure

Fixtures are organized by policy namespace and expected outcome:

- `release/` — release record rules
- `promotion/` — promotion log append-only rules
- `consistency/` — cross-file and directory/timestamp consistency rules

Each namespace has:
- `pass/` — fixtures that must pass
- `fail/` — fixtures that must fail

## Coverage requirements (enforced by CI)

For each namespace:
- `pass/` must contain at least one fixture
- `fail/` must contain at least one fixture

If a new policy file is added under `policies/*.rego`, corresponding fixtures must be added.

## Running tests locally

From the repository root:

```bash
conftest test policies/tests/release/pass/*.json -p policies -n release
conftest test policies/tests/release/fail/*.json -p policies -n release

conftest test policies/tests/promotion/pass/*.json -p policies -n promotion
conftest test policies/tests/promotion/fail/*.json -p policies -n promotion

conftest test policies/tests/consistency/pass/*.json -p policies -n consistency
conftest test policies/tests/consistency/fail/*.json -p policies -n consistency
```

## Regulated mode override in fixtures

Policies can derive regulated mode from compliance scope or accept an explicit override:

- Default: regulated mode = (gdpr == true OR pci == true)
- Override: add to input:

```json
"policy": { "regulated": true }
```

or

```json
"policy": { "regulated": false }
```

Downgrade override behavior requires additional fields/labels in real PR validation; fixtures should focus on the specific rule being tested.
