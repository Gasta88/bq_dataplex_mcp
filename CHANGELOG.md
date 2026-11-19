# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-19

### Added

- Hash-pinned `requirements.lock` (linux/amd64 target) that the Docker image
  installs with `pip --require-hashes`, so image builds are reproducible.
- Ruff and mypy configuration in `pyproject.toml`, plus a 93% coverage floor
  enforced in CI.
- `lint` CI job (ruff + mypy) and pip dependency caching for the Python jobs.
- README section showing a real MCP client call and the captured `ping`
  response, plus CI, license, and Python badges.
- This changelog.

### Changed

- Test job now runs `pytest --cov=app --cov-fail-under=93`.
- `CacheService` lookups in the metadata tools use a single `get()` instead of
  `has()` followed by `get()`.
- OAuth handlers narrow request parameters explicitly before use; behavior is
  unchanged except that a callback missing both `code` and `error` now returns
  a 502 error page instead of attempting a token exchange with a missing code.

### Security

- Local `denylist.txt` patterns remain gitignored and are documented in
  `denylist.txt.example`; the scanner is local-only and never runs in CI.
