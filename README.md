# Release Evidence Repository, Policy Engine

This repository hosts the **validation engine** used to enforce strict, non‑negotiable invariants for release evidence through:

- **OPA/Conftest Rego policies** (`policies/*.rego`)
- **Centralized policy configuration** (`policies/policy-settings.yml`)
- **Deterministic unit tests** (`policies/tests/**`) that guarantee non-regression

This repo does **not yet store release folders, artifacts, or evidence**.  
It currently focuses **exclusively** on the *policy layer* and its enforcement guarantees.
