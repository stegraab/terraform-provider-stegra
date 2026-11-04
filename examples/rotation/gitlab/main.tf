terraform {
  required_version = ">= 1.11"

  required_providers {
    gitlab = {
      source = "gitlabhq/gitlab"
    }
    stegra = {
      source = "stegraab/stegra"
    }
  }
}

provider "stegra" {}

resource "stegra_rotation" "gitlab" {
  rotation_period = "2160h" # 90 days

  # After consumers have switched to a newly reported active_generation,
  # record that generation here before the following rotation is due:
  # acknowledged_generation = 3
}

# GitLab's native rotate API immediately revokes the previous token. Two
# independent resources preserve one working token while the other is replaced.
resource "gitlab_project_access_token" "slot" {
  for_each = stegra_rotation.gitlab.slots

  project      = "my-group/my-project"
  name         = "terraform-rotation-${each.key}-${each.value.generation}"
  scopes       = ["read_api", "read_repository", "read_registry"]
  access_level = "reporter"

  # GitLab expires tokens at date precision; this can shorten the requested
  # lifetime by up to a day. Allow for that when choosing a rotation period.
  expires_at = formatdate("YYYY-MM-DD", each.value.expires_at)
}

output "active_token" {
  value     = gitlab_project_access_token.slot[stegra_rotation.gitlab.active_slot].token
  sensitive = true
}
