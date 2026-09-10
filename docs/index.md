---
page_title: "stegra Provider"
description: |-
  Terraform provider for Stegra platform control-plane resources.
---

# Stegra provider

The Stegra provider manages custom Stegra control-plane intent. The first
resource registers machine identities with the machine-enrollment service.

## Production authentication

Production enrollment uses short-lived Stegra access tokens. The provider calls
`stegra auth stegra` when it performs a registration operation and passes the
result only in the HTTP Authorization header. The token is never written into
Terraform configuration or state.

Configure the shared machine-enrollment endpoint once per Terraform workspace.
Nested resources inherit it through normal Terraform provider propagation:

```hcl
provider "stegra" {
  machine_enrollment_endpoint = "https://issuing-ca.example.internal/machine-enrollment"
  machine_enrollment_auth_url = "https://auth.example.internal"
}
```

The Stegra CLI reuses a valid cached login and opens the normal browser login
when necessary. The broker independently validates the token's signature,
issuer, audience, lifetime, and administrator role.

In CI, configure `STEGRA_OAUTH_TOKEN_ENDPOINT`, `STEGRA_OAUTH_CLIENT_ID`, and
`STEGRA_OAUTH_CLIENT_SECRET`. The provider uses the standard OAuth 2.0
client-credentials grant and caches the short-lived access token for the
Terraform process. It has no dependency on a particular authorization-server
implementation. The client secret is never sent to the enrollment service or
stored in Terraform state.

For local development only, set `machine_enrollment_token`. Static tokens are
restricted to loopback endpoints. HTTP and `insecure_skip_verify` are rejected
when using production OIDC authentication.

Provider attributes can be supplied through their corresponding environment
variables:

- `STEGRA_MACHINE_ENROLLMENT_ENDPOINT`
- `STEGRA_MACHINE_ENROLLMENT_AUTH_URL`
- `STEGRA_OAUTH_TOKEN_ENDPOINT`
- `STEGRA_OAUTH_CLIENT_ID`
- `STEGRA_OAUTH_CLIENT_SECRET`
- `STEGRA_MACHINE_ENROLLMENT_TOKEN`
- `STEGRA_INSECURE_SKIP_VERIFY`
