---
page_title: "stegra_oidc_id_token Ephemeral Resource"
description: "Obtains an OIDC ID token using the local Stegra CLI."
---

# stegra_oidc_id_token

Obtains an OIDC ID token during a Terraform operation. The Stegra CLI must be on
`PATH`. It reuses a valid local session or opens the browser for interactive
login. Terraform keeps the token out of state and saved plans.

```terraform
ephemeral "stegra_oidc_id_token" "local" {
  base_url  = "https://auth.example.com"
  realm     = "public"
  client_id = "terraform-local"
}

provider "harbor" {
  url          = "https://registry.example.com"
  insecure     = false
  bearer_token = ephemeral.stegra_oidc_id_token.local.id_token
}
```

## Schema

- `base_url` (String, required) The HTTPS base URL of the identity provider.
- `realm` (String, required) The OIDC realm name.
- `client_id` (String, required) The public OIDC client ID.
- `id_token` (String, sensitive, read-only) The ID token returned by the CLI.
