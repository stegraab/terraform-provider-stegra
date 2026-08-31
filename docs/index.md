---
page_title: "stegra Provider"
description: |-
  Terraform provider for Stegra platform control-plane resources.
---

# Stegra provider

The Stegra provider manages custom Stegra control-plane intent. The first
resource registers machine identities with the machine-enrollment service.

## Production authentication

Production enrollment uses a short-lived Step CA administrator identity. The
provider retrieves the configured JWK provisioner, creates an ephemeral
administrator certificate, and signs a fresh administrator JWT for each broker
request. The broker validates that JWT with Step CA.

```hcl
provider "stegra" {
  machine_enrollment_url = "https://issuing-ca.example.internal/machine-enrollment"

  step_ca_url               = "https://issuing-ca.example.internal"
  step_ca_admin_provisioner = "Admin JWK"
  step_ca_admin_subject     = "terraform-machine-enrollment"
  step_ca_admin_password    = var.step_ca_admin_password
}
```

For local development only, set `machine_enrollment_token` instead of the four
`step_ca_*` attributes. HTTP and `insecure_skip_verify` are rejected when using
production authentication.

Every attribute can be supplied through its corresponding environment variable:

- `STEGRA_MACHINE_ENROLLMENT_URL`
- `STEGRA_MACHINE_ENROLLMENT_TOKEN`
- `STEGRA_STEP_CA_URL`
- `STEGRA_STEP_CA_ADMIN_PROVISIONER`
- `STEGRA_STEP_CA_ADMIN_SUBJECT`
- `STEGRA_STEP_CA_ADMIN_PASSWORD`
- `STEGRA_INSECURE_SKIP_VERIFY`
