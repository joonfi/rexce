package release

is_bool(x) { type_name(x) == "boolean" }
is_string(x) { type_name(x) == "string" }

# Derived regulated status from compliance flags
derived_regulated {
  (input.release.compliance_scope.gdpr == true) or (input.release.compliance_scope.pci == true)
}

override_present { is_bool(input.policy.regulated) }

downgrade_override {
  override_present
  derived_regulated
  input.policy.regulated == false
}

# Effective regulated mode:
# - If override is present and allowed, use it
# - Else derive from compliance_scope

effective_regulated {
  override_present
  override_allowed
  input.policy.regulated == true
} else {
  override_present
  override_allowed
  input.policy.regulated == false
  false
} else {
  not override_present
  derived_regulated
}

# --- Override guardrails (downgrade only) ---
override_allowed {
  not downgrade_override
} else {
  downgrade_override
  has_label("regulatory-override-approved")
  has_nonempty(input.policy.reason)
  has_nonempty(input.policy.ticket)
  has_nonempty(input.policy.approved_by)
  is_rfc3339(input.policy.approved_at)
  is_rfc3339(input.policy.expires_at)
  expires_within_days(7)
  approvals_completed_for_role("security")
  approvals_completed_for_role("sre")
}

# Deny downgrade override without guardrails

deny[msg] {
  downgrade_override
  not has_label("regulatory-override-approved")
  msg := "Downgrade override requires PR label: regulatory-override-approved"
}

deny[msg] {
  downgrade_override
  not has_nonempty(input.policy.reason)
  msg := "Downgrade override requires policy.reason"
}

deny[msg] {
  downgrade_override
  not has_nonempty(input.policy.ticket)
  msg := "Downgrade override requires policy.ticket"
}

deny[msg] {
  downgrade_override
  not (has_nonempty(input.policy.approved_by) and is_rfc3339(input.policy.approved_at))
  msg := "Downgrade override requires policy.approved_by and policy.approved_at (RFC3339)"
}

deny[msg] {
  downgrade_override
  not (is_rfc3339(input.policy.expires_at) and expires_within_days(7))
  msg := "Downgrade override requires policy.expires_at (RFC3339) within 7 days"
}

deny[msg] {
  downgrade_override
  not approvals_completed_for_role("security")
  msg := "Downgrade override requires completed Security approval in approvals.required"
}

deny[msg] {
  downgrade_override
  not approvals_completed_for_role("sre")
  msg := "Downgrade override requires completed SRE approval in approvals.required"
}

# --- Required field validation ---

required_paths := [
  "release.id",
  "release.service",
  "release.created_at",
  "release.change_type",
  "release.risk_class",
  "release.compliance_scope.gdpr",
  "release.compliance_scope.pci",
  "source.repo",
  "source.commit_sha",
  "source.tag",
  "artifacts.container_image.name",
  "artifacts.container_image.digest",
  "artifacts.sbom.type",
  "artifacts.sbom.ref",
  "artifacts.provenance.ref",
  "quality.tests.unit",
  "quality.security.sast",
  "quality.policy.opa_conftest",
  "operational_readiness.slo.dashboard_url",
  "operational_readiness.runbook_url",
  "operational_readiness.rollback.strategy",
  "operational_readiness.rollback.triggers",
  "approvals.required"
]

deny[msg] {
  some p in required_paths
  not has_path(input, split(p, "."))
  msg := sprintf("Missing required field: %s", [p])
}

# Regulated-mode readiness requirements (effective)

deny[msg] {
  effective_regulated
  is_placeholder(input.operational_readiness.slo.dashboard_url)
  msg := "Regulated mode: slo.dashboard_url must be a real value (not placeholder)"
}

deny[msg] {
  effective_regulated
  is_placeholder(input.operational_readiness.runbook_url)
  msg := "Regulated mode: runbook_url must be a real value (not placeholder)"
}

deny[msg] {
  effective_regulated
  count(input.operational_readiness.rollback.triggers) < 2
  msg := "Regulated mode: rollback.triggers must contain at least 2 triggers"
}

# PCI-specific rule (derived from compliance scope)

deny[msg] {
  input.release.compliance_scope.pci == true
  input.release.risk_class != "high"
  msg := "PCI-scoped releases must have risk_class = high"
}

# Supply chain immutability

deny[msg] {
  not startswith(input.artifacts.container_image.digest, "sha256:")
  msg := "container_image.digest must start with sha256:"
}

# SBOM: SPDX only

deny[msg] {
  not is_string(input.artifacts.sbom.type)
  msg := "SBOM type must be present and a string"
}

deny[msg] {
  is_string(input.artifacts.sbom.type)
  input.artifacts.sbom.type != "spdx-json"
  msg := sprintf("SBOM type must be exactly spdx-json (got: %v)", [input.artifacts.sbom.type])
}

deny[msg] {
  ref := input.artifacts.sbom.ref
  not valid_evidence_ref(ref)
  msg := sprintf("SBOM ref must be a safe relative path under evidence/ (got: %s)", [ref])
}

deny[msg] {
  ref := input.artifacts.sbom.ref
  ref != "evidence/sbom.spdx.json"
  msg := sprintf("SBOM ref must be exactly evidence/sbom.spdx.json (got: %s)", [ref])
}

# Provenance reference

deny[msg] {
  ref := input.artifacts.provenance.ref
  not valid_evidence_ref(ref)
  msg := sprintf("Provenance ref must be a safe relative path under evidence/ (got: %s)", [ref])
}

deny[msg] {
  ref := input.artifacts.provenance.ref
  not allowed_provenance_ref(ref)
  msg := sprintf("Provenance ref must be an approved filename under evidence/ (got: %s)", [ref])
}

allowed_provenance_ref(ref) {
  ref == "evidence/provenance.intoto.jsonl"
} else {
  ref == "evidence/provenance.intoto.json"
}

# Inventory binding (optional)

has_inventory {
  input.inventory.files
  type_name(input.inventory.files) == "array"
}

inventory_has(path) {
  some i
  input.inventory.files[i] == path
}

deny[msg] {
  has_inventory
  ref := input.artifacts.sbom.ref
  not inventory_has(ref)
  msg := sprintf("SBOM ref points to missing file in evidence bundle: %s", [ref])
}

deny[msg] {
  has_inventory
  ref := input.artifacts.sbom.ref
  not inventory_has(sprintf("%s.sig", [ref]))
  msg := sprintf("Missing SBOM signature file: %s.sig", [ref])
}

deny[msg] {
  has_inventory
  ref := input.artifacts.sbom.ref
  not inventory_has(sprintf("%s.bundle", [ref]))
  msg := sprintf("Missing SBOM bundle file: %s.bundle", [ref])
}

deny[msg] {
  has_inventory
  ref := input.artifacts.provenance.ref
  not inventory_has(ref)
  msg := sprintf("Provenance ref points to missing file in evidence bundle: %s", [ref])
}

deny[msg] {
  has_inventory
  ref := input.artifacts.provenance.ref
  not inventory_has(sprintf("%s.sig", [ref]))
  msg := sprintf("Missing provenance signature file: %s.sig", [ref])
}

deny[msg] {
  has_inventory
  ref := input.artifacts.provenance.ref
  not inventory_has(sprintf("%s.bundle", [ref]))
  msg := sprintf("Missing provenance bundle file: %s.bundle", [ref])
}

# --- Helpers ---

has_label(lbl) {
  some i
  input.meta.pr_labels[i] == lbl
}

has_nonempty(v) {
  is_string(v)
  trim(v) != ""
  lower(v) != "tbd"
  not contains(lower(v), "todo")
  not contains(lower(v), "replace-me")
}

trim(s) := out {
  out := regex.replace("^\\s+|\\s+$", s, "")
}

is_rfc3339(ts) {
  is_string(ts)
  regex.match("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:Z|[+-]\\d{2}:\\d{2})$", ts)
}

parse_ns(ts) := ns {
  ns := time.parse_rfc3339_ns(ts)
}

expires_within_days(days) {
  a := input.policy.approved_at
  e := input.policy.expires_at
  parse_ns(e) >= parse_ns(a)
  (parse_ns(e) - parse_ns(a)) / 1000000000 <= days * 86400
}

approvals_completed_for_role(role) {
  some i
  a := input.approvals.required[i]
  lower(a.role) == role
  has_nonempty(a.approver)
  is_rfc3339(a.approved_at)
}

valid_evidence_ref(ref) {
  is_string(ref)
  startswith(ref, "evidence/")
  not startswith(ref, "/")
  not contains(ref, "://")
  not contains(ref, "..")
  not contains(ref, "\\")
}

is_placeholder(s) {
  is_string(s)
  contains(lower(s), "<")
} else {
  is_string(s)
  contains(lower(s), "replace-me")
} else {
  is_string(s)
  contains(lower(s), "todo")
} else {
  is_string(s)
  contains(lower(s), "example")
}

has_path(obj, path) {
  count(path) == 0
} else {
  key := path[0]
  rest := array.slice(path, 1, count(path))
  obj[key]
  has_path(obj[key], rest)
}
