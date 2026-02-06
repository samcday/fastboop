output "r2_bucket_name" {
  value       = cloudflare_r2_bucket.bleeding.name
  description = "R2 bucket name for bleeding snapshots."
}


output "worker_name" {
  value       = cloudflare_workers_script.bleeding.name
  description = "Workers script name for bleeding."
}

output "route_pattern" {
  value       = cloudflare_workers_route.bleeding.pattern
  description = "Workers route pattern."
}
