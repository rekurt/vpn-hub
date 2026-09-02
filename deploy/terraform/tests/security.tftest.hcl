mock_provider "digitalocean" {}

run "rejects_global_ssh_without_break_glass" {
  command = plan

  variables {
    do_token            = "0000000000000000000000000000000000000000000000000000000000000000"
    ssh_public_key_path = "tests/fixtures/terraform-test.pub"
    ssh_allowed_cidrs   = ["0.0.0.0/0"]
    allow_global_ssh    = false
  }

  expect_failures = [var.ssh_allowed_cidrs]
}

run "accepts_documentation_ssh_source" {
  command = plan

  variables {
    do_token            = "0000000000000000000000000000000000000000000000000000000000000000"
    ssh_public_key_path = "tests/fixtures/terraform-test.pub"
    ssh_allowed_cidrs   = ["198.51.100.10/32"]
    allow_global_ssh    = false
  }
}

run "allows_global_ssh_with_explicit_break_glass" {
  command = plan

  variables {
    do_token            = "0000000000000000000000000000000000000000000000000000000000000000"
    ssh_public_key_path = "tests/fixtures/terraform-test.pub"
    ssh_allowed_cidrs   = ["0.0.0.0/0", "::/0"]
    allow_global_ssh    = true
  }
}
