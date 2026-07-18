output "ipv4" {
  description = "Public address of the hub."
  value       = digitalocean_droplet.hub.ipv4_address
}

output "droplet_id" {
  description = "DigitalOcean droplet ID."
  value       = digitalocean_droplet.hub.id
}

output "ssh" {
  description = "Ready-to-paste SSH command."
  value       = "ssh root@${digitalocean_droplet.hub.ipv4_address}"
}
