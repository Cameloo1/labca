data "cloudflare_zone" "this" {
  filter = {
    name = var.zone_name
  }
}

# tunnel_secret is optional in provider v5, so it is omitted and Cloudflare
# generates it. config_src = "cloudflare" makes the tunnel remotely managed.
resource "cloudflare_zero_trust_tunnel_cloudflared" "labca" {
  account_id = var.account_id
  name       = var.tunnel_name
  config_src = "cloudflare"
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "labca" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.labca.id
}

locals {
  # origin_request is intentionally unset. cloudflared forwards the original
  # Host header by default and Traefik routes on it (PLATFORM_PLAN.md Appendix J).
  ingress_public = [{
    hostname = var.hostnames.public
    service  = var.traefik_service
  }]
  ingress_admin = var.access_enabled ? [{
    hostname = var.hostnames.admin
    service  = var.traefik_service
  }] : []
  ingress_catch_all = [{
    service = "http_status:404"
  }]
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "labca" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.labca.id

  config = {
    ingress = concat(local.ingress_public, local.ingress_admin, local.ingress_catch_all)
  }
}

resource "cloudflare_dns_record" "public" {
  zone_id = data.cloudflare_zone.this.id
  name    = var.hostnames.public
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.labca.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "managed by labca terraform"
}

resource "cloudflare_dns_record" "admin" {
  count = var.access_enabled ? 1 : 0

  zone_id = data.cloudflare_zone.this.id
  name    = var.hostnames.admin
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.labca.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "managed by labca terraform"
}

resource "cloudflare_zero_trust_access_policy" "admins" {
  count = var.access_enabled ? 1 : 0

  account_id       = var.account_id
  name             = "labca-admins"
  decision         = "allow"
  session_duration = "24h"

  include = [for e in var.admin_emails : {
    email = {
      email = e
    }
  }]

  lifecycle {
    precondition {
      condition     = length(var.admin_emails) > 0
      error_message = "access_enabled requires at least one entry in admin_emails."
    }
  }
}

resource "cloudflare_zero_trust_access_application" "admin" {
  count = var.access_enabled ? 1 : 0

  account_id           = var.account_id
  name                 = "labca-admin"
  domain               = var.hostnames.admin
  type                 = "self_hosted"
  session_duration     = "24h"
  app_launcher_visible = false

  policies = [{
    id         = cloudflare_zero_trust_access_policy.admins[0].id
    precedence = 1
  }]
}
