output "tunnel_id" {
  description = "Id of the Cloudflare Tunnel."
  value       = cloudflare_zero_trust_tunnel_cloudflared.labca.id
}

output "tunnel_token" {
  description = "Token that cloudflared uses to run this tunnel."
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.labca.token
  sensitive   = true
}

output "access_aud" {
  description = "Audience tag of the Access application, or empty when Access is disabled."
  value       = try(cloudflare_zero_trust_access_application.admin[0].aud, "")
  sensitive   = true
}
