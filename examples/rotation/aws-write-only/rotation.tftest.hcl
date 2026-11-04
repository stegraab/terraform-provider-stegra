mock_provider "aws" {}

run "create_write_only_slots" {
  command = apply

  assert {
    condition = {
      for key, version in aws_secretsmanager_secret_version.slot :
      key => version.secret_string_wo_version
      } == {
      "0" = 1
      "1" = 2
    }
    error_message = "write-only versions must match the Stegra slot generations"
  }
}

run "stable_plan" {
  command = plan

  assert {
    condition = alltrue([
      for key, version in aws_secretsmanager_secret_version.slot :
      version.secret_string_wo_version == stegra_rotation.example.slots[key].generation
    ])
    error_message = "stable plans must preserve write-only slot versions"
  }
}
