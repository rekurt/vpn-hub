variable "do_token" {
  description = "DigitalOcean API token with read/write scope. Supplied via TF_VAR_do_token; the Makefile reads it from the doctl configuration."
  type        = string
  sensitive   = true
}

variable "name" {
  description = "Name shared by the droplet, its firewall and the uploaded SSH key."
  type        = string
  default     = "vpn-hub-lab"
}

variable "region" {
  description = "DigitalOcean region slug."
  type        = string
  default     = "fra1"
}

variable "size" {
  description = "Droplet size slug. AmneziaWG needs very little; the DKMS build is the only heavy step."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "image" {
  description = "Base image. Ubuntu is the platform AmneziaWG publishes packages for; the Amnezia PPA does not install cleanly on Debian 13."
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "ssh_public_key_path" {
  description = "Public key granted root access to the hub."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "extra_ssh_key_fingerprints" {
  description = "Already-registered DigitalOcean SSH keys to add, by MD5 fingerprint, so a second workstation keeps access."
  type        = list(string)
  default     = []
}

variable "ssh_allowed_cidrs" {
  description = "Sources permitted to reach SSH at the cloud firewall. This value is required; use allow_global_ssh only for an explicit break-glass recovery."
  type        = list(string)

  validation {
    condition = alltrue([
      for cidr in var.ssh_allowed_cidrs : can(cidrhost(cidr, 0)) && (
        var.allow_global_ssh || !contains(["0.0.0.0/0", "::/0"], cidr)
      )
    ])
    error_message = "ssh_allowed_cidrs must contain valid CIDRs and cannot include 0.0.0.0/0 or ::/0 unless allow_global_ssh is true."
  }
}

variable "allow_global_ssh" {
  description = "Break-glass override permitting global SSH CIDRs. Keep false unless recovery access requires temporary global exposure."
  type        = bool
  default     = false
}

variable "wireguard_port" {
  description = "UDP port the AmneziaWG ingress listens on."
  type        = number
  default     = 51820
}
