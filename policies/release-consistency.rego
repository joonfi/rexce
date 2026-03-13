package consistency

is_bool(x) { type_name(x) == "boolean" }
is_string(x) { type_name(x) == "string" }

# Determine regulated mode based on release_record compliance scope, with optional override.

derived_regulated {
  rr := input.release_record
  (rr.release.compliance_scope.gdpr == true) or (rr.release.compliance_scope.pci == true)
}

override_present { is_bool(input.policy.regulated) }

downgrade_override {
  override_present
  derived_regulated
  input.policy.regulated == false
}

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

# Downgrade override guardrails (same as release-record policy)

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

# Require release_record input

deny[msg] {
  input.release_record == null
  msg := "Missing release_record in consistency validation input"
}

# Directory binding

deny[msg] {
  input.meta.release_dir_name != input.release_record.release.id
  msg := sprintf("Directory name must equal release.id (dir=%s id=%s)",
    [input.meta.release_dir_name, input.release_record.release.id])
}

# Path binding to created_at (strict): releases/YYYY/MM/<release.id>

deny[msg] {
  not created_at_has_ym_format
  msg := sprintf("release.created_at must be ISO-like 'YYYY-MM-...' (got: %v)", [input.release_record.release.created_at])
}

deny[msg] {
  created_at_has_ym_format
  expected := sprintf("releases/%s/%s/%s", [created_at_year, created_at_month, input.release_record.release.id])
  input.meta.release_dir_path != expected
  msg := sprintf("Directory path must equal %s (got: %s)", [expected, input.meta.release_dir_path])
}

created_at_has_ym_format {
  subs := regex.find_all_string_submatch("^(\\d{4})-(\\d{2})-", input.release_record.release.created_at)
  count(subs) > 0
}

created_at_year := y {
  subs := regex.find_all_string_submatch("^(\\d{4})-(\\d{2})-", input.release_record.release.created_at)
  y := subs[0][1]
}

created_at_month := m {
  subs := regex.find_all_string_submatch("^(\\d{4})-(\\d{2})-", input.release_record.release.created_at)
  m := subs[0][2]
}

# Cross-file IDs

deny[msg] {
  input.promotion_log != null
  input.promotion_log.promotion.release_id != input.release_record.release.id
  msg := "promotion.release_id must equal release.id"
}

deny[msg] {
  input.postdeploy != null
  input.postdeploy.postdeploy.release_id != input.release_record.release.id
  msg := "postdeploy.release_id must equal release.id"
}

# Process order: postdeploy cannot exist without promotion

deny[msg] {
  input.postdeploy != null
  input.promotion_log == null
  msg := "postdeploy-verification cannot exist without promotion-log"
}

# If regulated mode and promotion exists, require canary strategy

deny[msg] {
  effective_regulated
  input.promotion_log != null
  input.promotion_log.promotion.strategy != "canary"
  msg := "Regulated mode: promotion.strategy must be canary"
}

# Timestamp basics

is_rfc3339(ts) {
  is_string(ts)
  regex.match("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:Z|[+-]\\d{2}:\\d{2})$", ts)
}

parse_ns(ts) := ns {
  ns := time.parse_rfc3339_ns(ts)
}

postdeploy_finalized {
  input.postdeploy != null
  input.postdeploy.postdeploy.result != "TBD"
}

deny[msg] {
  postdeploy_finalized
  pd := input.postdeploy.postdeploy
  not (is_string(pd.window_end) and pd.window_end != "TBD" and is_rfc3339(pd.window_end))
  msg := "Finalized postdeploy requires window_end (RFC3339, not TBD)"
}

deny[msg] {
  postdeploy_finalized
  so := input.postdeploy.postdeploy.signoff
  not (is_string(so.signed_at) and so.signed_at != "TBD" and is_rfc3339(so.signed_at))
  msg := "Finalized postdeploy requires signoff.signed_at (RFC3339, not TBD)"
}

deny[msg] {
  postdeploy_finalized
  pd := input.postdeploy.postdeploy
  so := pd.signoff
  parse_ns(so.signed_at) < parse_ns(pd.window_end)
  msg := "signoff.signed_at must be >= postdeploy.window_end"
}

# Helpers reused for override guardrails

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

expires_within_days(days) {
  a := input.policy.approved_at
  e := input.policy.expires_at
  parse_ns(e) >= parse_ns(a)
  (parse_ns(e) - parse_ns(a)) / 1000000000 <= days * 86400
}

approvals_completed_for_role(role) {
  some i
  a := input.release_record.approvals.required[i]
  lower(a.role) == role
  has_nonempty(a.approver)
  is_rfc3339(a.approved_at)
}
