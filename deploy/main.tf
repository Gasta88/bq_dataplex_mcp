provider "google" {
  project = var.project_id
  region  = var.region
}

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
  backend "gcs" {}
}

# ---------------------------------------------------------------------------
# Required inputs
# ---------------------------------------------------------------------------

variable "project_id" {
  type        = string
  description = "GCP project that hosts the Cloud Run service and BigQuery datasets."
}

variable "image" {
  type        = string
  description = "Full container image reference including tag, e.g. REGION-docker.pkg.dev/PROJECT/REPO/bq-dataplex-mcp:0.1.0."
}

variable "service_account" {
  type        = string
  description = "Runtime service-account email. Leave empty to use the project's default compute service account."
  default     = ""
}

# ---------------------------------------------------------------------------
# Optional inputs
# ---------------------------------------------------------------------------

variable "region" {
  type        = string
  description = "Region for Cloud Run and BigQuery."
  default     = "us-central1"
}

variable "service_name" {
  type        = string
  description = "Cloud Run service name. The dev workspace appends -dev."
  default     = "bq-dataplex-mcp"
}

variable "invoker_members" {
  type        = list(string)
  description = "Principals granted roles/run.invoker. Empty keeps the service private. Use [\"allUsers\"] only when app-level OAuth is configured."
  default     = []
}

variable "bigquery_location" {
  type        = string
  description = "BigQuery job location (BIGQUERY_LOCATION)."
  default     = "us-central1"
}

variable "bigquery_reservation" {
  type        = string
  description = "Optional BigQuery reservation resource name. Empty uses on-demand billing."
  default     = ""
}

variable "audit_dataset" {
  type        = string
  description = "Dataset that receives the per-tool-call audit table. It must already exist."
  default     = "bq_audit"
}

variable "audit_queue_bound" {
  type        = number
  description = "Maximum number of audit rows buffered in memory before rows are dropped."
  default     = 1000
}

variable "cache_enabled" {
  type        = bool
  description = "Enable the in-process metadata result cache (CACHE_ENABLED)."
  default     = true
}

variable "min_instance_count" {
  type        = number
  description = "Minimum Cloud Run instances."
  default     = 0
}

variable "max_instance_count" {
  type        = number
  description = "Maximum Cloud Run instances."
  default     = 4
}

variable "labels" {
  type        = map(string)
  description = "Additional labels applied to the Cloud Run service."
  default     = {}
}

# OAuth 2.1 is optional. Terraform does not create the OAuth client, Secret
# Manager secrets, or the Firestore database; it only references existing
# secrets by name and passes their values as environment variables. See
# deploy/README.md for the manual setup.
variable "oauth_client_id_secret" {
  type        = string
  description = "Secret Manager secret name holding GOOGLE_OAUTH_CLIENT_ID. Empty disables app-level OAuth."
  default     = ""
}

variable "oauth_client_secret_secret" {
  type        = string
  description = "Secret Manager secret name holding GOOGLE_OAUTH_CLIENT_SECRET. Empty disables app-level OAuth."
  default     = ""
}

variable "oauth_base_url" {
  type        = string
  description = "Public base URL of the service (no trailing slash), used to build OAuth endpoints."
  default     = ""
}

variable "firestore_database_id" {
  type        = string
  description = "Firestore database ID backing the OAuth handshake store. Required when OAuth is enabled."
  default     = ""
}

variable "google_workspace_domain" {
  type        = string
  description = "Google Workspace hosted domain accepted by the JWT gate."
  default     = "example.com"
}

variable "google_oauth_service_account_email" {
  type        = string
  description = "Optional service-account email allowed to skip the Workspace hd check (must also present email_verified=true)."
  default     = ""
}

locals {
  is_dev       = terraform.workspace != "prod"
  stage        = local.is_dev ? "dev" : "prod"
  service_name = local.is_dev ? "${var.service_name}-dev" : var.service_name

  # OAuth is enabled only when both secret names are supplied.
  oauth_enabled = var.oauth_client_id_secret != "" && var.oauth_client_secret_secret != ""
}

resource "google_cloud_run_v2_service" "bq_dataplex_mcp" {
  name                = local.service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = !local.is_dev

  template {
    service_account = var.service_account != "" ? var.service_account : null

    scaling {
      min_instance_count = var.min_instance_count
      max_instance_count = var.max_instance_count
    }
    max_instance_request_concurrency = 20
    timeout                          = "3600s"

    containers {
      image = var.image

      ports {
        container_port = 8080
      }

      env {
        name  = "GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "LOG_LEVEL"
        value = "INFO"
      }
      env {
        name  = "DEPLOY_ENV"
        value = local.stage
      }
      env {
        name  = "BIGQUERY_LOCATION"
        value = var.bigquery_location
      }
      env {
        name  = "BIGQUERY_RESERVATION"
        value = var.bigquery_reservation
      }
      env {
        name  = "BQ_AUDIT_DATASET"
        value = var.audit_dataset
      }
      env {
        name  = "AUDIT_QUEUE_BOUND"
        value = tostring(var.audit_queue_bound)
      }
      env {
        name  = "CACHE_ENABLED"
        value = tostring(var.cache_enabled)
      }
      env {
        name  = "GOOGLE_WORKSPACE_DOMAIN"
        value = var.google_workspace_domain
      }
      env {
        name  = "GOOGLE_OAUTH_SERVICE_ACCOUNT_EMAIL"
        value = var.google_oauth_service_account_email
      }
      env {
        name  = "OAUTH_BASE_URL"
        value = local.oauth_enabled ? var.oauth_base_url : ""
      }
      env {
        name  = "FIRESTORE_DATABASE_ID"
        value = local.oauth_enabled ? var.firestore_database_id : ""
      }

      dynamic "env" {
        for_each = local.oauth_enabled ? [
          { name = "GOOGLE_OAUTH_CLIENT_ID", secret = var.oauth_client_id_secret },
          { name = "GOOGLE_OAUTH_CLIENT_SECRET", secret = var.oauth_client_secret_secret },
        ] : []
        content {
          name = env.value.name
          value_source {
            secret_key_ref {
              secret  = env.value.secret
              version = "latest"
            }
          }
        }
      }
    }
  }

  labels = merge(var.labels, { stage = local.stage, managed_by = "terraform" })
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  for_each = toset(var.invoker_members)

  name     = google_cloud_run_v2_service.bq_dataplex_mcp.name
  location = var.region
  role     = "roles/run.invoker"
  member   = each.value
}

# Counter for audit-queue overflow drops, scoped per environment through the
# service name label. app/audit.py logs the stable sentinel
# `audit_queue_overflow_dropped` as plain text.
resource "google_logging_metric" "audit_queue_overflow_dropped" {
  name   = "audit_queue_overflow_dropped-${local.stage}"
  filter = <<-EOT
    resource.type="cloud_run_revision" AND
    resource.labels.service_name="${local.service_name}" AND
    textPayload=~"audit_queue_overflow_dropped"
  EOT

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "Audit queue overflow drops (${local.stage})"
  }

  label_extractors = {}
}

output "service_url" {
  description = "Cloud Run URL for the service."
  value       = google_cloud_run_v2_service.bq_dataplex_mcp.uri
}
