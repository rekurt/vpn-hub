resource "digitalocean_ssh_key" "workstation" {
  name       = var.name
  public_key = file(pathexpand(var.ssh_public_key_path))
}

resource "digitalocean_droplet" "hub" {
  name   = var.name
  image  = var.image
  region = var.region
  size   = var.size

  # The hub blocks IPv6 end to end, so it should not have an address to leak from.
  ipv6       = false
  monitoring = true

  ssh_keys = concat(
    [digitalocean_ssh_key.workstation.fingerprint],
    var.extra_ssh_key_fingerprints,
  )

  # cloud-init only runs on first boot, so editing cloud-init.yaml must rebuild the
  # host rather than leave a droplet that silently no longer matches the code.
  user_data = file("${path.module}/cloud-init.yaml")
}

# A second, independent layer in front of the agent-managed nftables ruleset: if the
# agent is stopped or mid-reconcile, the hub still is not open to the internet.
resource "digitalocean_firewall" "hub" {
  name        = var.name
  droplet_ids = [digitalocean_droplet.hub.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_cidrs
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = tostring(var.wireguard_port)
    source_addresses = ["0.0.0.0/0"]
  }

  inbound_rule {
    protocol         = "icmp"
    source_addresses = ["0.0.0.0/0"]
  }

  # Egress is unrestricted: upstream tunnels dial arbitrary ports, and the routing
  # policy that decides what may leave is enforced on the host, not here.
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0"]
  }
}
