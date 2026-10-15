terraform {
  required_version = ">= 1.16.0, < 2.0.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.27"
    }
  }

  # State stays on the operator machine under .agent/, which is not committed.
  backend "local" {
    path = "../../.agent/tfstate/terraform.tfstate"
  }
}
