# Agent guide

## Project overview

`bq_dataplex_mcp` is a Python 3.11 FastMCP server for BigQuery and Dataplex. It
serves seven read-only tools over `streamable-http` and runs on Cloud Run. The
application lives in `app/`; Terraform for Cloud Run lives in `deploy/`.

## Conventions

- Target `linux/amd64`, base image `python:3.11-slim-bookworm`.
- Runtime dependencies go in `requirements.txt`; test-only dependencies go in
  `requirements-dev.txt`. Keep the Dockerfile minimal.
- Bump `VERSION` before merging to `main`. Its contents are the image tag.
- The image is environment-agnostic. All runtime configuration is read from
  environment variables by `app/config.py`'s `Settings` dataclass.
- Use full import paths inside `app` (`from app.config import settings`), never
  relative imports.
- Terraform workspaces are `dev` and `prod`. The `dev` workspace appends `-dev`
  to the service name and disables deletion protection.
- Use `terraform fmt` after editing `deploy/*.tf`; `terraform validate` must
  pass on both workspaces.
- Keep CI free of Google Cloud credentials. It runs tests, a Docker build,
  `terraform fmt`/`validate`, the denylist scan, and gitleaks.

## Editing guidelines

- Build context is the repository root (`docker build .`).
- Add a config knob in `app/config.py` first, then wire it into `deploy/main.tf`
  as a container env var if deployments should set it. Prefer safe defaults so
  importing `app.config` never raises.
- Secrets must come from Secret Manager or the environment; never commit
  secret values.
- Validate `dataset_id`/`table_id` and sanitize BigQuery errors through
  `app/validation.py`; do not leak raw API internals in tool responses.
- Route BigQuery-backed metadata results through
  `app/services/cache_service.py` (gated by `CACHE_ENABLED`). `execute_sql` is
  never cached.
- Tool descriptions are part of the public interface. Keep the three-part
  "Use this / Not this / Args" structure and update
  `tests/test_main.py`'s docstring assertions when they change.
- Run `pytest tests/ -v` before every push. The suite needs no credentials.
- Run `python scripts/check_denylist.py` before publishing changes.
- `scripts/smoke_test_dev.py` is the live, authenticated end-to-end check. It
  targets a deployed dev service only.

## Layout reminders

- `app/main.py` — `create_app()` factory, tool registration, transport.
- `app/audit.py` — audit decorator, deque, background flusher.
- `app/jwt_auth.py` / `app/google_auth.py` / `app/oauth_server.py` /
  `app/oauth_store.py` — optional OAuth 2.1 resource and authorization server.
- `app/services/` — thin wrappers around Google Cloud clients.
- `deploy/main.tf` — Cloud Run service, invoker IAM, audit overflow metric.
- `deploy/README.md` — deployment, IAM, OAuth setup.
