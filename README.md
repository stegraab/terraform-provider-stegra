# Terraform Provider for Stegra

Terraform provider for Stegra-specific platform control-plane resources.

The provider owns orchestration that does not naturally belong to an upstream
platform provider. Its first resource registers desired machine identity before
a VM proves its live platform and hardware-backed identity.

## Provider source

```hcl
terraform {
  required_providers {
    stegra = {
      source = "stegraab/stegra"
    }
  }
}
```

## Resources

- `stegra_machine_enrollment`

## Development

```bash
go test ./...
go build -o terraform-provider-stegra
```

See [provider documentation](./docs/index.md) and the
[`stegra_machine_enrollment` resource](./docs/resources/machine_enrollment.md).
