terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    random = {
      source = "hashicorp/random"
    }
    stegra = {
      source = "stegraab/stegra"
    }
  }
}

provider "stegra" {}

resource "stegra_rotation" "example" {
  rotation_period = "2160h"
}

resource "aws_secretsmanager_secret" "slot" {
  for_each = stegra_rotation.example.slots
  name     = "example/rotating-token-${each.key}"
}

# Each ephemeral password exists only for this Terraform operation. A
# production configuration should retrieve an immutable generation from Vault
# or another durable secret backend instead of generating it here.
ephemeral "random_password" "slot" {
  for_each = stegra_rotation.example.slots

  length  = 32
  special = true
}

resource "aws_secretsmanager_secret_version" "slot" {
  for_each = stegra_rotation.example.slots

  secret_id                = aws_secretsmanager_secret.slot[each.key].id
  secret_string_wo         = ephemeral.random_password.slot[each.key].result
  secret_string_wo_version = each.value.generation
}

output "active_secret_arn" {
  value = aws_secretsmanager_secret.slot[stegra_rotation.example.active_slot].arn
}
