---
page_title: "stegra Provider"
description: |-
  Terraform provider for Stegra platform control-plane resources.
---

# Stegra provider

The Stegra provider manages custom Stegra control-plane intent. The first
resource registers machine identities with the machine-enrollment service.

## Production authentication

Production enrollment uses the standard AWS credential chain. This supports
environment credentials, AWS IAM Identity Center profiles, and workload or
instance roles without placing credentials in Terraform configuration or state.

For every broker operation, the provider signs an AWS STS `GetCallerIdentity`
request using SigV4. The signed proof is bound to the broker URL, exact request
method and URL, request-body hash, and a random nonce. The broker verifies those
bindings, prevents nonce replay, calls AWS STS, and authorizes the returned IAM
principal against its server-side policy.

Configure the shared machine-enrollment endpoint once per Terraform workspace.
Nested resources inherit it through normal Terraform provider propagation:

```hcl
provider "stegra" {
  machine_enrollment_endpoint = "https://issuing-ca.example.internal/machine-enrollment"
  aws_profile                 = "dev-boden-se"
}
```

The provider intentionally has no AWS credential attributes. `aws_profile` is
only a non-secret selector for the standard AWS shared-config chain and lets a
workspace use the same short-lived SSO or runner credentials as its AWS
provider. It falls back to `AWS_PROFILE` and then the default AWS credential
chain. A region must be available through that same chain.

For local development only, set `machine_enrollment_token`. HTTP and
`insecure_skip_verify` are rejected when using production AWS IAM authentication.

Provider attributes can be supplied through their corresponding environment
variables:

- `STEGRA_MACHINE_ENROLLMENT_ENDPOINT`
- `STEGRA_MACHINE_ENROLLMENT_TOKEN`
- `STEGRA_INSECURE_SKIP_VERIFY`
- `AWS_PROFILE`
