terraform {
  required_providers {
    nutanix = {
      source = "nutanix/nutanix"
    }
    stegra = {
      source = "stegraab/stegra"
    }
  }
}

provider "stegra" {
  machine_enrollment_url = "https://issuing-ca.example.internal/machine-enrollment"
}

resource "stegra_machine_enrollment" "vm" {
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
