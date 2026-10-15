variable "account_id" {
  description = "Cloudflare account id (32 lowercase hex characters)."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "account_id must be 32 lowercase hex characters."
  }
}

variable "zone_name" {
  description = "Name of the existing Cloudflare zone, for example example.com."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.zone_name))
    error_message = "zone_name must be a lowercase DNS name without a trailing dot."
  }
}

variable "hostnames" {
  description = "Public and admin hostnames. Both must sit inside zone_name."
  type = object({
    public = string
    admin  = string
  })

  validation {
    condition = (
      endswith(var.hostnames.public, ".${var.zone_name}") &&
      endswith(var.hostnames.admin, ".${var.zone_name}")
    )
    error_message = "Both hostnames must end with .<zone_name>."
  }

  validation {
    condition     = var.hostnames.public != var.hostnames.admin
    error_message = "The public and admin hostnames must differ."
  }
}

variable "admin_emails" {
  description = "Email addresses allowed through Cloudflare Access to the admin hostname."
  type        = list(string)
  default     = []
  sensitive   = false

  validation {
    condition     = alltrue([for e in var.admin_emails : can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", e))])
    error_message = "Each entry in admin_emails must look like an email address."
  }
}

variable "access_enabled" {
  description = "Publish the admin hostname behind Cloudflare Access. Requires admin_emails."
  type        = bool
  default     = false
}

variable "tunnel_name" {
  description = "Name of the Cloudflare Tunnel."
  type        = string
  default     = "labca"
}

variable "traefik_service" {
  description = "In-cluster URL of the Traefik service that receives tunnel traffic."
  type        = string
  default     = "http://traefik.kube-system.svc.cluster.local:80"
}
