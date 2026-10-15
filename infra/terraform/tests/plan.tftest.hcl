mock_provider "cloudflare" {
  mock_data "cloudflare_zone" {
    defaults = {
      id = "11111111111111111111111111111111"
    }
  }

  mock_data "cloudflare_zero_trust_tunnel_cloudflared_token" {
    defaults = {
      token = "mock-token"
    }
  }

  mock_resource "cloudflare_zero_trust_tunnel_cloudflared" {
    defaults = {
      id = "22222222-2222-2222-2222-222222222222"
    }
  }

  mock_resource "cloudflare_zero_trust_access_policy" {
    defaults = {
      id = "33333333-3333-3333-3333-333333333333"
    }
  }
}

variables {
  account_id = "00000000000000000000000000000000"
  zone_name  = "example.com"
  hostnames = {
    public = "ca.example.com"
    admin  = "admin.ca.example.com"
  }
}

run "access_disabled" {
  command = plan

  variables {
    access_enabled = false
    admin_emails   = []
  }

  assert {
    condition     = cloudflare_dns_record.public.name == "ca.example.com" && length(cloudflare_dns_record.admin) == 0
    error_message = "Only the public DNS record should exist when Access is disabled."
  }

  assert {
    condition     = length(cloudflare_zero_trust_access_application.admin) == 0 && length(cloudflare_zero_trust_access_policy.admins) == 0
    error_message = "No Access resources should exist when Access is disabled."
  }

  assert {
    condition     = length(cloudflare_zero_trust_tunnel_cloudflared_config.labca.config.ingress) == 2
    error_message = "Expected two ingress rules when Access is disabled."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.labca.config.ingress[0].hostname == "ca.example.com"
    error_message = "The public hostname rule must come first."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.labca.config.ingress[1].service == "http_status:404"
    error_message = "The catch-all rule must be last."
  }
}

run "access_enabled" {
  command = plan

  variables {
    access_enabled = true
    admin_emails   = ["admin@example.com"]
  }

  assert {
    condition     = length(cloudflare_dns_record.admin) == 1 && cloudflare_dns_record.admin[0].name == "admin.ca.example.com"
    error_message = "Expected a second DNS record for the admin hostname."
  }

  assert {
    condition     = length(cloudflare_zero_trust_access_application.admin) == 1
    error_message = "Expected exactly one Access application."
  }

  assert {
    condition     = cloudflare_zero_trust_access_application.admin[0].domain == var.hostnames.admin
    error_message = "The Access application must protect the admin hostname."
  }

  assert {
    condition     = cloudflare_zero_trust_access_application.admin[0].session_duration == "24h"
    error_message = "The Access session duration must be 24h."
  }

  assert {
    condition     = length(cloudflare_zero_trust_tunnel_cloudflared_config.labca.config.ingress) == 3
    error_message = "Expected three ingress rules when Access is enabled."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.labca.config.ingress[1].hostname == "admin.ca.example.com"
    error_message = "The admin rule must follow the public rule."
  }

  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.labca.config.ingress[2].service == "http_status:404"
    error_message = "The catch-all rule must be last."
  }
}

run "access_enabled_without_emails" {
  command = plan

  variables {
    access_enabled = true
    admin_emails   = []
  }

  expect_failures = [
    cloudflare_zero_trust_access_policy.admins,
  ]
}

run "hostname_outside_zone" {
  command = plan

  variables {
    hostnames = {
      public = "ca.other.org"
      admin  = "admin.ca.example.com"
    }
  }

  expect_failures = [
    var.hostnames,
  ]
}
