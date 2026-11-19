# Agent guide

## Project overview

`bq_dataplex_mcp` is a Python 3.11 FastMCP server for BigQuery and Dataplex. It
serves seven read-only tools over `streamable-http` and runs on Cloud Run. The
application lives in `app/`; Terraform for Cloud Run lives in `deploy/`.

## Conventions

- Target `linux/amd64`, base image `python:3.11-slim-bookworm`.
- Runtime dependencies go in `requirements.txt`; test-only dependencies go in
  `requirements-dev.txt`. Keep the Dockerfile minimal.
- `requirements.lock` is generated from `requirements.txt` and installed by the
  Dockerfile with `--require-hashes`. Regenerate it whenever `requirements.txt`
  changes:
  `uv pip compile requirements.txt --generate-hashes --python-version 3.11 --python-platform x86_64-unknown-linux-gnu --output-file requirements.lock`.
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
  `terraform fmt`/`validate`, and gitleaks. The denylist scan is local-only and
  not part of CI.

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
- Run `ruff check app tests` and `mypy app` before every push; CI enforces both
  plus a 93% coverage floor (`--cov=app --cov-fail-under=93`).
- Run `python scripts/check_denylist.py` before publishing changes. It reads the
  gitignored `denylist.txt` (create it from `denylist.txt.example`); never commit
  the real patterns.
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
