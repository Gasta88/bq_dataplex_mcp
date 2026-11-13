# Deploying with Terraform

Flat, non-module Terraform for the `bq-dataplex-mcp` Cloud Run service. Two
workspaces (`dev` and `prod`) share the same configuration; `dev` appends
`-dev` to the service name and disables deletion protection.

Terraform manages the Cloud Run service, its invoker IAM bindings, and an
optional Cloud Logging counter for audit-queue overflows. It does **not**
create the container image, the runtime service account, BigQuery datasets,
Artifact Registry, OAuth clients, Secret Manager secrets, or the Firestore
database.

## Prerequisites

- Terraform 1.5+
- `gcloud` authenticated against the target project, or `GOOGLE_APPLICATION_CREDENTIALS`
- A container image already pushed to a registry Cloud Run can pull from
- A GCS bucket for Terraform state (or remove the `backend "gcs" {}` block and
  use local state)
- An existing BigQuery dataset for audit rows (default: `bq_audit`)

## Configure

```bash
cd deploy
cp dev.gcs.tfbackend.example dev.gcs.tfbackend
cp prod.gcs.tfbackend.example prod.gcs.tfbackend
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` (`project_id` and `image` are required) and the
backend files. `*.gcs.tfbackend` and `terraform.tfvars` are gitignored.

## Deploy

```bash
make plan  ENV=dev
make apply ENV=dev
```

`image` comes from `terraform.tfvars` by default. Pass it per invocation with
`IMAGE=...` to override.

For prod, use `ENV=prod`. `make init` selects or creates the matching Terraform
workspace.

Destroy:

```bash
make destroy ENV=dev IMAGE=...
```

## Variables

| Variable | Default | Purpose |
|---|---|---|
| `project_id` | required | GCP project |
| `image` | required | Full container image reference |
| `service_account` | `""` | Runtime SA; empty uses the default compute SA |
| `region` | `us-central1` | Cloud Run and BigQuery region |
| `service_name` | `bq-dataplex-mcp` | Base service name; dev gets `-dev` |
| `invoker_members` | `[]` | Principals with `roles/run.invoker` |
| `bigquery_location` | `us-central1` | BigQuery job location |
| `bigquery_reservation` | `""` | Reservation path; empty uses on-demand |
| `audit_dataset` | `bq_audit` | Dataset for the audit table (must exist) |
| `audit_queue_bound` | `1000` | In-memory audit row bound |
| `cache_enabled` | `true` | Metadata result cache |
| `min_instance_count` | `0` | Minimum instances |
| `max_instance_count` | `4` | Maximum instances |
| `labels` | `{}` | Extra labels on the service |
| `oauth_client_id_secret` | `""` | Existing Secret Manager secret name |
| `oauth_client_secret_secret` | `""` | Existing Secret Manager secret name |
| `oauth_base_url` | `""` | Public service URL for OAuth endpoints |
| `firestore_database_id` | `""` | Firestore database for OAuth state |
| `google_workspace_domain` | `example.com` | Accepted Workspace domain |
| `google_oauth_service_account_email` | `""` | Optional `hd`-check exemption |

## Runtime configuration

The container receives these env vars from Terraform: `GCP_PROJECT`,
`LOG_LEVEL`, `DEPLOY_ENV`, `BIGQUERY_LOCATION`, `BIGQUERY_RESERVATION`,
`BQ_AUDIT_DATASET`, `AUDIT_QUEUE_BOUND`, `CACHE_ENABLED`,
`GOOGLE_WORKSPACE_DOMAIN`, `GOOGLE_OAUTH_SERVICE_ACCOUNT_EMAIL`,
`OAUTH_BASE_URL`, and `FIRESTORE_DATABASE_ID`.

OAuth secret values are injected from Secret Manager only when both
`oauth_client_id_secret` and `oauth_client_secret_secret` are set.

> **Prod fails closed without OAuth.** When `DEPLOY_ENV=prod` and
> `GOOGLE_OAUTH_CLIENT_ID` is empty, `create_app()` raises at startup. Set the
> OAuth variables (or use the `dev` workspace) before applying prod.

## Permissions

The runtime service account needs, at minimum:

| Tool | Role |
|---|---|
| `list_datasets`, `list_tables`, `get_table_metadata` | `roles/bigquery.metadataViewer` (or broader read) |
| `execute_sql` | `roles/bigquery.jobUser` plus read access to queried data |
| `execute_sql` with a reservation | `roles/bigquery.user` |
| `get_data_lineage` | `roles/datalineage.viewer` |
| `get_data_quality_results` | `roles/dataplex.dataScanViewer` |
| Audit flusher | `roles/bigquery.dataEditor` on the audit dataset |
| Cloud Logging | `roles/logging.logWriter` |

Grant IAM outside this Terraform configuration.

## Optional OAuth 2.1 setup

The app can act as its own OAuth authorization server for MCP clients. To
enable it, create the following outside Terraform:

1. A Google Cloud OAuth 2.0 web application client. Add
   `https://<service-url>/oauth/callback` as an authorized redirect URI.
2. Secret Manager secrets holding the client ID and client secret.
3. A Firestore (Native mode) database for the OAuth handshake store.
4. IAM for the runtime service account: `roles/secretmanager.secretAccessor`
   on the two secrets and `roles/datastore.user` on the project.

Then set `oauth_client_id_secret`, `oauth_client_secret_secret`,
`oauth_base_url`, `firestore_database_id`, and `google_workspace_domain`.

With OAuth enabled, `invoker_members` can safely be `["allUsers"]` because every
`/mcp` request is validated by the app. Without OAuth, keep
`invoker_members` empty (or limited to named principals).

## Audit table

The flusher writes to
`<project>.<audit_dataset>.bq_dataplex_mcp_audit_tool_called`. Create the
dataset before deploying. If the table is missing or writes fail, each row is
logged as a WARNING and dropped without affecting tool responses.

The `google_logging_metric.audit_queue_overflow_dropped` resource counts the
`audit_queue_overflow_dropped` sentinel per environment. A sustained non-zero
value means `audit_queue_bound` is too small or the flusher is falling behind.

## CI

CI runs tests, a Docker build, `terraform fmt -check`, and `terraform validate`.
It does not authenticate to GCP, push images, or apply Terraform. Publication
and deployment are left to the operator.
