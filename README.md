# bq_dataplex_mcp

[![CI](https://github.com/Gasta88/bq_dataplex_mcp/actions/workflows/ci.yaml/badge.svg)](https://github.com/Gasta88/bq_dataplex_mcp/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)

An MCP (Model Context Protocol) server for BigQuery and Dataplex. It exposes a
`streamable-http` endpoint that gives MCP clients read-only access to BigQuery
metadata, ad-hoc SQL, table lineage, and Dataplex data-quality results.

The service is a Python 3.11 FastMCP application packaged as a `linux/amd64`
container and designed to run on Cloud Run. Terraform for Cloud Run is included,
but the application itself is environment-agnostic: all configuration arrives
through environment variables.

## Tools

### Liveness
- `ping()` — returns `{"status": "ok", "service": "bq-dataplex-mcp"}`

### Metadata and discovery
- `list_datasets()` — all BigQuery datasets in the configured project.
- `list_tables(dataset_id)` — all tables in a dataset.
- `get_table_metadata(dataset_id, table_id)` — schema, description, clustering,
  partitioning, row/byte counts, labels, and timestamps.

### Query execution
- `execute_sql(query, max_rows=None, max_bytes_billed=None, dry_run=False)` —
  executes a single read-only `SELECT`/`WITH` statement. DML/DDL is rejected
  before any BigQuery call. Every real run carries a `maximum_bytes_billed` cap
  (default 100 GiB) and optionally routes through a BigQuery reservation.
  Responses include bytes processed and an on-demand-equivalent cost estimate.
  `dry_run=True` returns the estimate without billing. Results are never cached.

### Lineage and quality
- `get_data_lineage(dataset_id, table_id)` — upstream/downstream lineage at
  three levels plus a Mermaid `graph LR` diagram.
- `get_data_quality_results(dataset_id, table_id)` — latest Dataplex DataScan
  result, including pass/fail and dimension scores.

The metadata, lineage, and quality tools use an in-memory, process-lifetime
cache for identical arguments. `ping` and `execute_sql` are never cached.

## Connecting a client

Point any streamable-HTTP MCP client at `/mcp`. Claude Desktop and most other
clients accept a JSON server definition:

```json
{
  "mcpServers": {
    "bq-dataplex": {
      "type": "http",
      "url": "https://<cloud-run-service-url>/mcp"
    }
  }
}
```

Or call it directly with the FastMCP Python client:

```python
import asyncio

from fastmcp import Client


async def main() -> None:
    async with Client("http://localhost:8080/mcp") as client:
        print(await client.list_tools())
        print(await client.call_tool("ping", {}))


asyncio.run(main())
```

`ping` is the only tool that needs no Google Cloud credentials, so it is the
fastest end-to-end check. Its response, captured from a local run:

```json
{"status": "ok", "service": "bq-dataplex-mcp"}
```

The data tools return structured results in the same shape. For example, an
`execute_sql` real run returns rows plus the schema and the cost figures:

```json
{
  "rows": [{"dataset_id": "analytics", "table_count": 12}],
  "rowCount": 1,
  "schema": [{"name": "dataset_id", "type": "STRING", "mode": "NULLABLE"},
             {"name": "table_count", "type": "INTEGER", "mode": "NULLABLE"}],
  "totalBytesProcessed": "2097152",
  "cacheHit": false,
  "jobId": "job_example",
  "estimatedCostUsd": 0.000011920928955078125
}
```

That second payload is illustrative; only the `ping` response above was captured
verbatim. The remaining tools need Application Default Credentials, described
under [Local development](#local-development).

## Layout

```
.
├── Dockerfile
├── requirements.txt
├── requirements.lock
├── VERSION
├── CHANGELOG.md
├── app/
│   ├── config.py              # env-driven Settings
│   ├── validation.py          # identifier and read-only SQL validation
│   ├── audit.py               # per-tool-call BigQuery audit logging
│   ├── jwt_auth.py            # Google Workspace ID-token verification
│   ├── google_auth.py         # Google OAuth helpers
│   ├── oauth_server.py        # MCP OAuth authorization-server surface
│   ├── oauth_store.py         # Firestore-backed OAuth state
│   ├── rejection_log.py       # protocol-layer rejection logging
│   ├── pricing.py             # BigQuery cost arithmetic
│   ├── services/              # BigQuery, Dataplex, lineage, cache clients
│   └── main.py                # FastMCP entrypoint and tool registration
├── deploy/                    # Terraform for Cloud Run
├── docs/                      # design notes
├── scripts/                   # smoke test, manual checks, denylist scanner
└── tests/                     # pytest suite (GCP clients mocked)
```

## Configuration

All runtime configuration is injected as environment variables.

| Variable | Default | Notes |
|---|---|---|
| `GCP_PROJECT` | `""` | Project used for BigQuery, Dataplex, and lineage clients. |
| `LOG_LEVEL` | `INFO` | Python log level. |
| `DEPLOY_ENV` | `dev` | `dev` or `prod`. In `prod`, startup fails if OAuth is not configured. |
| `PORT` | `8080` | HTTP listen port. |
| `BIGQUERY_LOCATION` | `us-central1` | BigQuery job location. |
| `BIGQUERY_RESERVATION` | `""` | Optional reservation path for `execute_sql`. Empty uses on-demand billing. |
| `CACHE_ENABLED` | `true` | In-process metadata cache. |
| `BQ_AUDIT_DATASET` | `bq_audit` | Dataset for the audit table. |
| `AUDIT_QUEUE_BOUND` | `1000` | In-memory audit row bound. |
| `BQ_PRICE_PER_TIB_USD` | `6.25` | Price used for the cost estimate. |
| `GOOGLE_OAUTH_CLIENT_ID` | `""` | OAuth client ID; enables the auth layer. |
| `GOOGLE_OAUTH_CLIENT_SECRET` | `""` | OAuth client secret. |
| `GOOGLE_WORKSPACE_DOMAIN` | `example.com` | Accepted Google Workspace hosted domain. |
| `GOOGLE_OAUTH_SERVICE_ACCOUNT_EMAIL` | `""` | Optional service-account email allowed to skip the `hd` check. |
| `JWKS_CACHE_TTL_SECONDS` | `3600` | Google JWKS cache TTL. |
| `OAUTH_BASE_URL` | `""` | Public base URL used to build OAuth endpoints. |
| `FIRESTORE_DATABASE_ID` | `""` | Firestore database for OAuth state. |
| `FIRESTORE_TIMEOUT_SECONDS` | `5` | Per-call Firestore timeout. |

## Authentication

When `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` are set, every
request on `/mcp` must carry a Google-signed ID token that passes signature,
expiry, `aud`, and `hd` validation. The app also publishes its own OAuth
discovery, Dynamic Client Registration, authorization, callback, token, and
revocation endpoints under `/oauth/*` and `/.well-known/*`. Those routes are
pre-auth by design.

The OAuth token returned to MCP clients is the raw Google ID token, so the same
JWT validation runs on every `/mcp` request. A configured service-account email
can skip the Workspace `hd` requirement, but only when its `email_verified`
claim is exactly `true`; the audience check is never relaxed.

If OAuth is not configured, the app runs without an app-level gate. In that
mode, restrict access with Cloud Run IAM (`invoker_members`) or a private
network.

## Audit logging

Every tool call enqueues one row containing the caller's verified email, tool
name, request/response payloads, latency, timestamp, and (for `execute_sql`)
bytes processed and estimated cost. A background task flushes rows to
`<project>.<BQ_AUDIT_DATASET>.bq_dataplex_mcp_audit_tool_called`. Failed writes
are logged and dropped without affecting the tool response.

If the in-memory queue reaches `AUDIT_QUEUE_BOUND`, new rows are dropped and a
stable `audit_queue_overflow_dropped` WARNING is emitted. The Terraform
configuration can turn that sentinel into a Cloud Logging metric.

The cost estimate is informational. With a flat-rate reservation there is no
true per-byte price, so the figure is a notional cost-attribution proxy rather
than an actual bill.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m app.main
```

`ping` needs no Google Cloud credentials. The other tools need Application
Default Credentials with access to the target project:

```bash
gcloud auth application-default login
```

Run the tests:

```bash
pytest tests/ -v
```

The suite mocks BigQuery, Dataplex, lineage, and Firestore clients, so it needs
no credentials and makes no network calls.

Build the image:

```bash
docker build -t bq-dataplex-mcp:local .
```

## Deployment

`deploy/` contains a flat Terraform configuration for Cloud Run. It creates the
service, invoker IAM bindings, and an optional audit-overflow metric. Container
images, service accounts, BigQuery datasets, Secret Manager secrets, and
Firestore databases are managed outside Terraform.

```bash
cd deploy
cp dev.gcs.tfbackend.example dev.gcs.tfbackend
cp terraform.tfvars.example terraform.tfvars
make plan  ENV=dev IMAGE=<full-image-reference>
make apply ENV=dev IMAGE=<full-image-reference>
```

See [`deploy/README.md`](deploy/README.md) for variables, required IAM roles,
OAuth setup, and the prod fail-closed behavior.

## Smoke test

`scripts/smoke_test_dev.py` resolves a deployed dev Cloud Run URL, starts an
authenticated `gcloud run services proxy`, and exercises all seven tools:

```bash
python scripts/smoke_test_dev.py --project my-project
```

## CI

GitHub Actions runs ruff, mypy, the test suite with a 93% coverage floor, a
validation-only Docker build, `terraform fmt`/`validate` and a gitleaks secret
scan. It does not authenticate to Google Cloud or deploy anything. The denylist
scan is local-only: copy `denylist.txt.example` to the gitignored
`denylist.txt` and run `python scripts/check_denylist.py` before pushing.

Run the quality gates locally with:

```bash
ruff check app tests
mypy app
pytest tests/ -v --cov=app --cov-report=term-missing --cov-fail-under=93
```

`requirements.txt` holds the human-edited ranges; `requirements.lock` is the
hash-pinned resolution the Docker image installs with `--require-hashes`.
Regenerate it after changing `requirements.txt`:

```bash
uv pip compile requirements.txt --generate-hashes \
  --python-version 3.11 --python-platform x86_64-unknown-linux-gnu \
  --output-file requirements.lock
```

## License

MIT. See [LICENSE](LICENSE).
