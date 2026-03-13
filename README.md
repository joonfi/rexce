# Release Evidence Repository

This repository stores **release evidence** for production deployments, including release metadata, promotion history, and post-deployment verification.

Evidence is submitted via pull requests and validated automatically.

## Repository structure
Evidence is organized under:

`releases/YYYY/MM/REL-YYYY-MM-DD-NNN/`

A release folder may include:
- `release-record.yml` — canonical release metadata and evidence references
- `promotion-log.yml` — rollout history (append-only)
- `postdeploy-verification.yml` — post-deployment verification outcome and signoff
- `evidence/` — SBOM, provenance, test summaries, security summaries, policy summaries
- `.sig` / `.bundle` files for each evidence artifact

## Validation model
Pull requests are validated to ensure:
- Release records follow required schema and evidence reference rules
- Promotion logs are append-only (no edits to historical steps)
- Cross-file consistency is maintained (IDs, directory structure, timestamps)
- Required artifacts exist
- Required artifacts are cryptographically signed and signatures verify successfully
- Policy changes do not regress behavior (policy regression tests + coverage enforcement)

## Signature verification
The validator verifies signatures using repository secrets:
- `COSIGN_CERT_ISSUER`
- `COSIGN_CERT_IDENTITY`

## Regulated mode override
By default, regulated mode is derived from:
- `release.compliance_scope.gdpr == true` OR `release.compliance_scope.pci == true`

You may explicitly override by adding a `policy` section to `release-record.yml`:

```yaml
policy:
  regulated: true|false
  reason: "..."
  ticket: "..."
  approved_by: "..."
  approved_at: "YYYY-MM-DDTHH:MM:SSZ"
  expires_at: "YYYY-MM-DDTHH:MM:SSZ"
```

Notes:
- `regulated: true` is always allowed (stricter checks).
- `regulated: false` is treated as a downgrade and requires:
  - PR label `regulatory-override-approved`
  - reason, ticket, approver, timestamps, expiry
  - completed Security + SRE approvals
  - expiry within **7 days** of `approved_at`

## Notes you’ll likely customize
Replace placeholders in upstream pipelines with your production tooling:
- artifact push + digest extraction
- SBOM/provenance generation
- test/security scan integrations

Ensure timestamps use RFC3339 format:
- `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS+08:00`
