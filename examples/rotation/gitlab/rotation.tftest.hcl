mock_provider "gitlab" {}

run "create_staggered_tokens" {
  command = apply

  assert {
    condition = formatdate(
      "YYYY-MM-DD",
      stegra_rotation.gitlab.slots["0"].expires_at,
    ) == formatdate("YYYY-MM-DD", timeadd(plantimestamp(), "2160h"))
    error_message = "slot 0 must initially request expiration in 90 days"
  }

  assert {
    condition = formatdate(
      "YYYY-MM-DD",
      stegra_rotation.gitlab.slots["1"].expires_at,
    ) == formatdate("YYYY-MM-DD", timeadd(plantimestamp(), "1440h"))
    error_message = "slot 1 must initially request expiration in 60 days"
  }

  assert {
    condition     = stegra_rotation.gitlab.rotation_interval == "720h0m0s"
    error_message = "two 90-day slots must rotate every 30 days"
  }

  assert {
    condition     = !stegra_rotation.gitlab.rollout_pending
    error_message = "the initial generation must be acknowledged automatically"
  }
}

run "stable_plan" {
  command = plan

  assert {
    condition = alltrue([
      for key, token in gitlab_project_access_token.slot :
      token.expires_at == formatdate(
        "YYYY-MM-DD",
        stegra_rotation.gitlab.slots[key].expires_at,
      )
    ])
    error_message = "GitLab expiration must remain equal to stable rotation state"
  }
}
