# Policy Decision Record (PDR) Specification

A PDR is an audit-grade artifact produced by the consumer gate. It captures:
- consumer repo+SHA and run metadata
- rexec repo+ref pinned
- policy/settings file hashes used
- validated evidence directories
- required refs verified
- wrapper inputs used for conftest
- conftest logs and cosign verification log
- final pass/fail summary

PDR must be uploaded even on failure.

Required structure under `pdr/`:
- meta.json
- rer-policy-sha256.txt
- evidence-dirs.txt
- required-refs.txt
- result.json
- summary.md
- logs/ (release, promotion, consistency, cosign)
- inputs/ (copies of wrapper JSON per validated directory)