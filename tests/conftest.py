"""Shared pytest fixtures for the test suite.

Two layers of protection keep an ambient `GOOGLE_OAUTH_CLIENT_ID` (or the other
OAuth env vars) in a developer's shell from leaking into the tests:

1. A module-level scrub at import time. `app.main`'s module-level `mcp`
   singleton is constructed during pytest collection, before any fixture runs.
   This block guarantees the shared instance is built auth-disabled.
2. An autouse fixture that re-clears the same env vars before every test, in
   case an earlier test's `monkeypatch.setenv` outlived its teardown. It also
   resets the audit deque and BigQuery client, which are process-wide state.
"""

import os

import pytest

_OAUTH_ENV_VARS = (
    "GOOGLE_OAUTH_CLIENT_ID",
    "GOOGLE_OAUTH_CLIENT_SECRET",
    "GOOGLE_WORKSPACE_DOMAIN",
    "JWKS_CACHE_TTL_SECONDS",
    "OAUTH_BASE_URL",
    "FIRESTORE_DATABASE_ID",
)

# Layer 1: runs at conftest.py import time (pytest collection), before any
# test module's `import app.main` -- see module docstring.
for _name in _OAUTH_ENV_VARS:
    os.environ.pop(_name, None)


@pytest.fixture(autouse=True)
def _clear_oauth_env_vars(monkeypatch):
    # Layer 2: see module docstring.
    for name in _OAUTH_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _clear_audit_deque():
    """Clear `app.audit`'s shared module-level audit state before and after
    every test function. `_audit_deque`/`_bq_client` are
    process-wide state (not per-test-module), so this must be a repo-wide
    autouse fixture here rather than one scoped locally to
    `tests/test_audit.py` -- it also isolates the audit-deque assertions in
    `tests/test_mcp_auth_integration.py`'s audit-email test and guards against
    any accidental cross-test leakage into `tests/test_main.py`.
    """
    import app.audit as audit_module

    audit_module._audit_deque.clear()
    audit_module._bq_client = None
    yield
    audit_module._audit_deque.clear()
    audit_module._bq_client = None
