# Credential rotation examples

The examples all use the same `stegra_rotation` generation contract:

- `local` is self-contained apart from provider downloads and is the quickest
  way to observe slot alternation.
- `gitlab` creates independent project access tokens with a fresh expiration
  date on each slot replacement and delivers the preferred token through an
  ordinary GitLab resource. Token values are stored in Terraform state.
- `aws-write-only` passes ephemeral passwords into AWS Secrets Manager's
  `secret_string_wo` argument, with the numeric Stegra generation used as
  `secret_string_wo_version`.

After distributing a newly active credential, set
`acknowledged_generation` to that slot's generation. The next rotation is
blocked until this acknowledgement is present. Changing `size` deliberately
replaces the coordinator and its generations; no implicit slot migration is
attempted.

Build and select the development provider as described in `local/README.md`.
Then validate any example with:

```sh
TF_CLI_CONFIG_FILE=/tmp/stegra-provider.tfrc terraform init -backend=false
TF_CLI_CONFIG_FILE=/tmp/stegra-provider.tfrc terraform validate
```

The GitLab and AWS examples create real external resources when applied. Set
their normal provider credentials and review the plan before applying them.
They are intentionally not applied by the provider test suite.

The AWS example uses ephemeral random passwords only to demonstrate Terraform's
write-only value flow. For a production multi-consumer rotation, retrieve each
immutable slot generation from a durable secret backend so retries receive the
same value.
