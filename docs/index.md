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

Production provider configuration can therefore remain empty: `provider
"stegra" {}`. The machine-enrollment endpoint is configured on the resource
that owns the integration.

The provider intentionally has no AWS credential attributes. Select credentials
using the standard AWS environment and shared-config mechanisms, such as
`AWS_PROFILE`. A region must be available through that same chain.

For local development only, set `machine_enrollment_token`. HTTP and
`insecure_skip_verify` are rejected when using production AWS IAM authentication.

The local-development attributes can be supplied through their corresponding
environment variables:

- `STEGRA_MACHINE_ENROLLMENT_TOKEN`
- `STEGRA_INSECURE_SKIP_VERIFY`
