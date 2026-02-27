provider "cloudflare" {}

provider "github" {
  owner = var.github_owner
}

data "cloudflare_zones" "primary" {
  filter {
    name   = var.zone_name
    status = "active"
  }
}

data "cloudflare_api_token_permission_groups" "all" {}

locals {
  zone_id = one(data.cloudflare_zones.primary.zones).id
  r2_bucket_item_write = coalesce(
    lookup(data.cloudflare_api_token_permission_groups.all.r2, "Workers R2 Storage Bucket Item Write", null),
    lookup(data.cloudflare_api_token_permission_groups.all.r2, "Workers R2 Storage Write", null)
  )
}

resource "cloudflare_r2_bucket" "bleeding" {
  account_id = var.account_id
  name       = var.r2_bucket_name
}


resource "cloudflare_workers_script" "bleeding" {
  account_id = var.account_id
  name       = var.worker_name
  content    = file("${path.module}/worker.js")

  r2_bucket_binding {
    name        = "R2_BUCKET"
    bucket_name = cloudflare_r2_bucket.bleeding.name
  }

  dynamic "secret_text_binding" {
    for_each = var.artifact_proxy_github_token == "" ? [] : [var.artifact_proxy_github_token]
    content {
      name = "GITHUB_TOKEN"
      text = secret_text_binding.value
    }
  }
}

resource "cloudflare_workers_route" "bleeding" {
  zone_id     = local.zone_id
  pattern     = "${var.hostname}/*"
  script_name = cloudflare_workers_script.bleeding.name
}

resource "cloudflare_workers_route" "www" {
  zone_id     = local.zone_id
  pattern     = "${var.www_hostname}/*"
  script_name = cloudflare_workers_script.bleeding.name
}

resource "cloudflare_record" "bleeding" {
  zone_id         = local.zone_id
  name            = var.hostname
  type            = "A"
  content         = "192.0.2.1"
  proxied         = true
  allow_overwrite = true
}

resource "cloudflare_record" "www" {
  zone_id         = local.zone_id
  name            = var.www_hostname
  type            = "A"
  content         = "192.0.2.1"
  proxied         = true
  allow_overwrite = true
}


resource "cloudflare_record" "docs" {
  zone_id         = local.zone_id
  name            = var.docs_hostname
  type            = "CNAME"
  content         = var.github_pages_cname_target
  proxied         = false
  allow_overwrite = true
}

resource "cloudflare_api_token" "r2_bleeding" {
  name = "fastboop-bleeding-r2"

  lifecycle {
    precondition {
      condition     = local.r2_bucket_item_write != null
      error_message = "R2 permission group not found. Check cloudflare_api_token_permission_groups.r2 keys."
    }
  }

  policy {
    permission_groups = [local.r2_bucket_item_write]
    resources = {
      "com.cloudflare.edge.r2.bucket.${var.account_id}_default_${cloudflare_r2_bucket.bleeding.name}" = "*"
    }
  }
}

resource "github_actions_secret" "r2_access_key_id" {
  repository      = var.github_repo
  secret_name     = "R2_ACCESS_KEY_ID"
  plaintext_value = cloudflare_api_token.r2_bleeding.id
}

resource "github_actions_secret" "r2_secret_access_key" {
  repository      = var.github_repo
  secret_name     = "R2_SECRET_ACCESS_KEY"
  plaintext_value = sha256(cloudflare_api_token.r2_bleeding.value)
}

resource "github_actions_secret" "r2_bucket" {
  repository      = var.github_repo
  secret_name     = "R2_BUCKET"
  plaintext_value = cloudflare_r2_bucket.bleeding.name
}

resource "github_actions_secret" "r2_endpoint_url" {
  repository      = var.github_repo
  secret_name     = "R2_ENDPOINT_URL"
  plaintext_value = "https://${var.account_id}.r2.cloudflarestorage.com"
}

resource "github_actions_secret" "tofu_state_passphrase" {
  repository      = var.github_repo
  secret_name     = "TF_VAR_state_passphrase"
  plaintext_value = var.state_passphrase
}
