# Outputs are grouped by what they are for: connecting to the platform,
# configuring the workloads, and the manual follow-up steps a two-phase apply
# leaves behind.

# ---------------------------------------------------------------------------
# Access
# ---------------------------------------------------------------------------

output "kubectl_credentials" {
  description = "Run this to point kubectl at the cluster."
  value       = module.gke.get_credentials_command
}

output "api_endpoint" {
  value = "https://${var.api_hostname}.${var.domain}"
}

output "mtproto_endpoint" {
  description = "TCP and UDP on 4443."
  value       = "${module.lb_network.mtproto_hostname}:4443"
}

output "cdn_endpoint" {
  value = "https://${var.cdn_hostname}.${var.domain}"
}

output "dns_name_servers" {
  description = "Set these as the NS records at the domain registrar. Nothing resolves until this is done."
  value       = module.network.dns_name_servers
}

# ---------------------------------------------------------------------------
# Workload configuration
# ---------------------------------------------------------------------------
#
# These feed the kustomize overlays. `terraform output -json workload_env`
# renders a map that scripts/render-env.sh turns into a ConfigMap.

output "workload_env" {
  description = "Environment variables the services need, derived from the infrastructure."
  value = {
    GCP_PROJECT_ID = var.project_id
    GCP_REGION     = var.region
    ENV            = var.env

    KAFKA_BROKERS = module.kafka.bootstrap_servers
    KAFKA_TLS     = "true"
    KAFKA_OAUTH   = "true"

    REDIS_ADDRS   = join(",", module.memorystore.discovery_endpoints)
    REDIS_CLUSTER = "true"
    REDIS_TLS     = "true"

    CLOUDSQL_CONNECTION_NAME = module.cloudsql.connection_name
    POSTGRES_DSN             = module.cloudsql.dsn_via_proxy

    MEDIA_BUCKET         = module.storage.media_bucket
    PUBLIC_BUCKET        = module.storage.public_bucket
    AUDIT_ARCHIVE_BUCKET = module.storage.audit_archive_bucket
    CDN_HOST             = "${var.cdn_hostname}.${var.domain}"

    IMAGE_REPOSITORY = module.artifact_registry.repository_url
  }
  sensitive = false
}

output "workload_service_accounts" {
  description = "Annotate each Kubernetes ServiceAccount with iam.gke.io/gcp-service-account set to the matching value."
  value       = module.iam.workload_service_accounts
}

output "secret_ids" {
  description = "Secret Manager ids. Seed the values with scripts/bootstrap-secrets.sh."
  value       = module.secrets.secret_ids
}

output "image_repository" {
  value = module.artifact_registry.repository_url
}

# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

output "nat_egress_ips" {
  description = "Static source addresses for outbound calls. Give these to any third party that allowlists."
  value       = module.network.nat_ips
}

output "cloudbuild_service_account" {
  value = module.iam.cloudbuild_service_account
}

output "clouddeploy_service_account" {
  value = module.iam.clouddeploy_service_account
}

output "certificate_status_command" {
  value = module.lb_https.certificate_status_command
}

# ---------------------------------------------------------------------------
# Second-apply inputs
# ---------------------------------------------------------------------------

output "next_steps" {
  description = "What to do after the first apply."
  value       = <<-EOT
    1. Point the registrar at these name servers:
         ${join("\n         ", module.network.dns_name_servers)}

    2. Seed the secrets (Terraform deliberately never holds their values):
         ./scripts/bootstrap-secrets.sh ${var.project_id} ${var.env}

    3. Get cluster credentials:
         ${module.gke.get_credentials_command}

    4. Deploy the workloads:
         kubectl apply -k deploy/k8s/overlays/${var.env}

    5. Find the NEG the Gateway controller created and the realtime pool's
       instance groups, then re-apply with them set:

         gcloud compute network-endpoint-groups list \
           --project ${var.project_id} --filter="name~messaging" \
           --format="value(name,zone)"

         gcloud container node-pools describe realtime-pool \
           --cluster ${module.gke.cluster_name} --region ${var.region} \
           --project ${var.project_id} --format="value(instanceGroupUrls)"

       Set api_neg_name, api_neg_zone and realtime_instance_groups in the
       environment's tfvars and apply again. Until then the load balancers
       exist but have no backends.

    6. Watch the managed certificate reach ACTIVE (up to an hour):
         ${module.lb_https.certificate_status_command}
  EOT
}
