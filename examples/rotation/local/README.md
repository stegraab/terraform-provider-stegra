# Local rotation example

This example proves the legacy/stateful integration without calling any Stegra
API. Build the provider and configure a Terraform development override first.

```sh
mkdir -p /tmp/stegra-provider
go build -o /tmp/stegra-provider/terraform-provider-stegra ../../..

cat > /tmp/stegra-provider.tfrc <<'EOF'
provider_installation {
  dev_overrides {
    "stegraab/stegra" = "/tmp/stegra-provider"
  }
  direct {}
}
EOF

TF_CLI_CONFIG_FILE=/tmp/stegra-provider.tfrc terraform init
TF_CLI_CONFIG_FILE=/tmp/stegra-provider.tfrc terraform apply -auto-approve
```

Use a short period to observe alternation:

```sh
TF_CLI_CONFIG_FILE=/tmp/stegra-provider.tfrc terraform apply -auto-approve -var rotation_period=4s
sleep 2
TF_CLI_CONFIG_FILE=/tmp/stegra-provider.tfrc terraform apply -auto-approve -var rotation_period=4s
```

Only one slot generation and one password fingerprint change during the second
apply. Confirm that consumers have switched to the new active generation, then
acknowledge that generation before the next scheduled rotation. For example, if
the output reports active generation `3`:

```sh
TF_CLI_CONFIG_FILE=/tmp/stegra-provider.tfrc terraform apply -auto-approve \
  -var rotation_period=4s \
  -var acknowledged_generation=3
```

An unacknowledged rollout holds the following rotation and its deadline produces
a warning. Run
`terraform output rotation` and `terraform output password_fingerprints` to
inspect the non-secret evidence. `active_password` is marked sensitive, but its
password is still stored in Terraform state by design.
