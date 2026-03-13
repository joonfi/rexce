# File: policies/promotion-log-appendonly.rego
# Metadata Header
# Title: promotion-log-appendonly.rego
# Owner(s): SRE, Security, Repo Owners
# Reviewed: 2026-03-13T00:00:00Z
# Purpose: Enforce append-only promotion history; required canary stages when regulated.
# Guardrails: Historical steps must not change; regulated canary stages present.
# Inputs: { "base": {..}|null, "head": {..} }; Data via -d policies/policy-settings.yml
# Outputs: deny[] on mutation or reordering.

package promotion

config := data["policy-settings"].policy

########################
# Structure checks
########################

deny[msg] {
  not head_has_required_shape
  msg := "promotion-log invalid structure: expected promotion.release_id and promotion.steps"
}

head_has_required_shape {
  input.head.promotion.release_id
  input.head.promotion.steps
}

########################
# Append-only enforcement (prefix-equal)
########################

base_exists {
  input.base != null
  input.base.promotion.steps
}

deny[msg] {
  base_exists
  not prefix_equal
  msg := "promotion-log must be append-only: existing steps modified/removed/reordered"
}

prefix_equal {
  base_steps := input.base.promotion.steps
  head_steps := input.head.promotion.steps
  count(head_steps) >= count(base_steps)
  not exists_diff(base_steps, head_steps)
}

exists_diff(base_steps, head_steps) {
  some i
  i < count(base_steps)
  base_steps[i] != head_steps[i]
}

########################
# Regulated canary stages
########################

required_stage(stage) {
  stage := config.promotion.regulated_canary_stages[_]
}

stage_present(stage) {
  some i
  input.head.promotion.steps[i].traffic == stage
}

deny[msg] {
  input.head.promotion.regulated == true
  stage := required_stage(stage)
  not stage_present(stage)
  msg := sprintf("Regulated promotion requires canary stage %s", [stage])
}
