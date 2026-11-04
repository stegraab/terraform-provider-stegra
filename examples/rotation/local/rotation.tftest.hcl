run "create" {
  command = apply

  variables {
    rotation_period = "2160h"
    rotation_size   = 2
  }

  assert {
    condition     = !stegra_rotation.example.rollout_pending
    error_message = "the initial active generation must be acknowledged automatically"
  }
}

run "longer_policy_does_not_postpone" {
  command = apply

  variables {
    rotation_period = "2880h"
    rotation_size   = 2
  }

  assert {
    condition = timecmp(
      stegra_rotation.example.next_rotation_at,
      run.create.rotation.next_rotation_at,
    ) <= 0
    error_message = "a longer policy must not postpone an already scheduled rotation"
  }
}

run "shorter_period_preserves_existing_passwords" {
  command = apply

  variables {
    rotation_period = "48h"
    rotation_size   = 2
  }

  assert {
    condition     = stegra_rotation.example.slots == run.create.rotation.slots
    error_message = "changing the period must preserve both existing slot generations and expirations"
  }

  assert {
    condition     = output.password_fingerprints == run.create.password_fingerprints
    error_message = "changing the period must not replace the existing passwords"
  }

  assert {
    condition     = stegra_rotation.example.rotation_interval == "16h0m0s"
    error_message = "the new two-day period must schedule rotations sixteen hours apart"
  }
}

run "size_change_replaces" {
  command = plan

  variables {
    rotation_period = "2160h"
    rotation_size   = 3
  }

  assert {
    condition     = length(stegra_rotation.example.slots) == 3
    error_message = "replacement must initialize the newly requested slot count"
  }
}
