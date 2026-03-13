package promotion

# Expects input:
# { "base": {..} | null, "head": {..} }

required_stages := {"1%","5%","25%","50%","100%"}

deny[msg] {
  not head_has_required_shape
  msg := "promotion-log invalid structure: expected promotion.release_id and promotion.steps"
}

head_has_required_shape {
  input.head.promotion.release_id
  input.head.promotion.steps
}

# Append-only enforcement

deny[msg] {
  base_exists
  not prefix_equal
  msg := "promotion-log must be append-only: existing steps modified/removed/reordered"
}

base_exists {
  input.base != null
  input.base.promotion.steps
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

# Required canary stages when regulated

deny[msg] {
  input.head.promotion.regulated == true
  missing := missing_stage
  msg := sprintf("Regulated promotion requires canary stage %s in promotion steps", [missing])
}

missing_stage := s {
  s := stage
  stage := stages[_]
  not stage_present(stage)
  stages := set_to_array(required_stages)
}

stage_present(stage) {
  some i
  input.head.promotion.steps[i].traffic == stage
}

set_to_array(s) = a {
  a := [x | x := s[_]]
}
