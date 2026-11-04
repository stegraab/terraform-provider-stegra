terraform {
  required_version = ">= 1.11"

  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
    stegra = {
      source = "stegraab/stegra"
    }
  }
}

variable "rotation_period" {
  description = "Use 4s to watch the example alternate quickly; use 2160h for 90 days."
  type        = string
  default     = "2160h"
}

variable "rotation_size" {
  description = "Number of independently valid password slots."
  type        = number
  default     = 2
}

variable "acknowledged_generation" {
  description = "Preferred generation confirmed as deployed to consumers."
  type        = number
  default     = null
  nullable    = true
}

provider "stegra" {}

resource "stegra_rotation" "example" {
  rotation_period         = var.rotation_period
  size                    = var.rotation_size
  acknowledged_generation = var.acknowledged_generation
}

# This is the compatibility path for ordinary Terraform resources. The
# passwords and every resource that consumes them are necessarily in state.
resource "random_password" "slot" {
  for_each = stegra_rotation.example.slots

  length  = 32
  special = true

  keepers = {
    generation = each.value.generation
  }
}

output "rotation" {
  value = {
    id                      = stegra_rotation.example.id
    size                    = stegra_rotation.example.size
    slots                   = stegra_rotation.example.slots
    active_slot             = stegra_rotation.example.active_slot
    active_generation       = stegra_rotation.example.active_generation
    acknowledged_generation = stegra_rotation.example.acknowledged_generation
    rollout_pending         = stegra_rotation.example.rollout_pending
    rollout_deadline        = stegra_rotation.example.rollout_deadline
    rotate_before           = stegra_rotation.example.rotate_before
    rollout_timeout         = stegra_rotation.example.rollout_timeout
    rotation_interval       = stegra_rotation.example.rotation_interval
    next_rotation_at        = stegra_rotation.example.next_rotation_at
  }
}

output "active_password" {
  description = "Example ordinary value. Sensitive redacts display but does not keep it out of state."
  value       = random_password.slot[stegra_rotation.example.active_slot].result
  sensitive   = true
}

# Short one-way fingerprints make the example observable without printing the
# generated passwords. They are for this local demonstration only; consumers
# should use the password values, not their fingerprints.
output "password_fingerprints" {
  value = {
    for slot, password in random_password.slot :
    slot => nonsensitive(substr(sha256(password.result), 0, 12))
  }
}
