---
page_title: "stegra_machine_enrollment Resource"
---

# stegra_machine_enrollment

Registers desired machine identity before the machine proves possession of its
platform and hardware-backed attestors. Registration is authorization intent,
not attestation; the enrollment service still verifies live inventory,
anti-spoofing controls, NGT possession, TPM credential activation and a
nonce-bound PCR quote.

```hcl
resource "stegra_machine_enrollment" "vm" {
  endpoint          = "https://issuing-ca.example.internal/machine-enrollment"
  attestor_type     = "nutanix-vtpm"
  attestor_identity = nutanix_virtual_machine_v2.vm.bios_uuid

  attestor_claims = {
    vm_ext_id       = nutanix_virtual_machine_v2.vm.ext_id
    generation_uuid = nutanix_virtual_machine_v2.vm.generation_uuid
    vtpm_disk_id    = nutanix_virtual_machine_v2.vm.vtpm_disk_id
    nic_ext_id      = nutanix_virtual_machine_v2.vm.nics[0].ext_id
    mac_address     = nutanix_virtual_machine_v2.vm.nics[0].nic_backing_info[0].virtual_ethernet_nic[0].mac_address
    ip_address      = nutanix_virtual_machine_v2.vm.nics[0].nic_network_info[0].virtual_ethernet_nic_network_info[0].ipv4_config[0].ip_address[0].value
  }

  machine_identity = "host/example.dev.se-bod.stegra.tech"
  ssh_principals   = ["example", "example.dev.se-bod.stegra.tech"]
}
```

The resource is platform-generic. `attestor_type` selects a server-side
verifier, while `attestor_identity` and `attestor_claims` carry immutable string
facts supplied by the relevant platform provider. The Stegra provider does not
import or depend on the Nutanix provider.

For `nutanix-vtpm`, the service currently requires `vm_ext_id`,
`generation_uuid`, `vtpm_disk_id`, `nic_ext_id`, `mac_address`, and `ip_address`.
The BIOS UUID is the attestor identity observable inside the VM. These facts do
not themselves prove possession; the broker re-reads all six claims from Prism
and then performs NGT and TPM attestation.

All configurable attributes require replacement. Deleting the Terraform
resource revokes the registration while retaining its server-side audit record.
Expired or revoked registrations remain in state with a warning so Terraform
never silently authorizes a new identity. After investigation, recover with an
explicit `terraform apply -replace=stegra_machine_enrollment.vm`.

For incident response, set `revoked = true` and apply. This revokes the
registration without removing it from Terraform state, preventing later normal
applies from recreating it. Revocation is deliberately one-way. To recover after
investigation, remove `revoked = true` and use the explicit replacement command
above.

## Arguments

- `endpoint` — machine-enrollment API base URL. Production AWS-IAM authentication requires HTTPS with certificate verification.
- `attestor_type` — server-side platform verifier type.
- `attestor_identity` — stable identity observable by the attesting machine.
- `attestor_claims` — immutable platform facts verified during attestation.
- `machine_identity` — requested machine identity.
- `ssh_principals` — requested SSH host principals.
- `revoked` — optional one-way emergency revocation switch; defaults to `false`.

## Read-only attributes

- `id` — enrollment registration identifier.
- `status` — registration lifecycle status.
