# The API token is read from the CLOUDFLARE_API_TOKEN environment variable.
# It is never a Terraform variable and never written to a file.
provider "cloudflare" {}
