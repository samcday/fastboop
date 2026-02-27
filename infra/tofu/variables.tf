variable "account_id" {
  type        = string
  description = "Cloudflare account ID."
  default     = "444c14b123bd021dcdf0400fbd847d63"
}

variable "zone_name" {
  type        = string
  description = "Cloudflare zone name."
  default     = "fastboop.win"
}

variable "hostname" {
  type        = string
  description = "Hostname for the bleeding site."
  default     = "bleeding.fastboop.win"
}

variable "www_hostname" {
  type        = string
  description = "Hostname for the public web frontend."
  default     = "www.fastboop.win"
}

variable "worker_name" {
  type        = string
  description = "Workers script name."
  default     = "fastboop-bleeding"
}

variable "r2_bucket_name" {
  type        = string
  description = "R2 bucket name for bleeding snapshots."
  default     = "fastboop-bleeding"
}

variable "github_owner" {
  type        = string
  description = "GitHub repository owner."
  default     = "samcday"
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name."
  default     = "fastboop"
}

variable "artifact_proxy_github_token" {
  type        = string
  description = "Optional GitHub token for /<project>/gha/* worker proxies (needs Actions:read on the source repositories)."
  default     = ""
  sensitive   = true
}

variable "state_passphrase" {
  type        = string
  description = "Passphrase for OpenTofu state encryption (min 16 chars)."
  sensitive   = true
}

variable "docs_hostname" {
  type        = string
  description = "Hostname for user-facing docs (GitHub Pages)."
  default     = "docs.fastboop.win"
}

variable "github_pages_cname_target" {
  type        = string
  description = "DNS target for GitHub Pages custom domain."
  default     = "samcday.github.io"
}
