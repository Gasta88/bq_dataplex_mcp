"""Input validation and error-message sanitization for the MCP tools.

Dataset and table IDs are validated against BigQuery's identifier rules.
BigQuery error messages are sanitized before they reach a tool response so
credential-file paths and raw API internals are never leaked.

`validate_sql_query` enforces the read-only, single-statement contract with
`sqlglot` (a real BigQuery SQL parser) instead of regex keyword matching. This
closes the bypass class where a comment hides a string boundary (or vice
versa), which two independent regex passes cannot reliably handle.
"""

from __future__ import annotations

import re

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

_ID_PATTERN = re.compile(r"[a-zA-Z0-9_]+")
_MAX_ID_LENGTH = 1024
_CREDENTIALS_FILE_PATTERN = re.compile(r"/[^\s]+\.json")

_MAX_QUERY_LENGTH = 1_000_000
_SQL_DIALECT = "bigquery"
# Node types that indicate a write/DDL/administrative statement rather than a
# pure read query. Checked against the *root* of the single parsed statement,
# not via keyword regex -- a real parser (rather than two independent regex
# passes for comment-stripping and string-literal-masking) closes the whole
# class of bypass where a comment hides a string boundary or vice versa:
# two regex passes each blind to the other's syntax produced real
# read-only-enforcement bypasses in code review.
_FORBIDDEN_STATEMENT_TYPES = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.TruncateTable,
    exp.Alter,
    exp.Grant,
    exp.Command,
    exp.Export,
    exp.LoadData,
    # `SELECT ... INTO <target>` is only valid inside a BigQuery scripting
    # block (assigning a script variable); BigQuery's Jobs API itself rejects
    # it as a standalone query. Rejected here anyway as defense-in-depth
    # rather than relying on that external behavior to hold.
    exp.Into,
)


def validate_dataset_id(value: object) -> str:
    """Validate a BigQuery dataset ID.

    Must be a non-empty string, at most 1024 characters, containing only
    letters, numbers, and underscores. Mirrors the reference implementation's `validateDatasetId` exactly.
    """
    return _validate_id(value, label="Dataset ID")


def validate_table_id(value: object) -> str:
    """Validate a BigQuery table ID.

    Must be a non-empty string, at most 1024 characters, containing only
    letters, numbers, and underscores. Mirrors the reference implementation's `validateTableId` exactly.
    """
    return _validate_id(value, label="Table ID")


def validate_sql_query(value: object) -> str:
    """Validate a caller-supplied BigQuery SQL query for read-only execution.

    Type/non-empty check, a 1,000,000-character length cap, then parses the
    query with `sqlglot` (BigQuery dialect) rather than approximating SQL
    syntax with regex: a query that fails to parse, that parses to anything
    other than exactly one statement (comments and empty statements between
    stray semicolons don't count), or whose statement is not rooted in a
    `SELECT`/`WITH` node is rejected. Returns the trimmed *original* query
    string -- the parsed AST is used only for classification, never returned
    or executed.

    This is the sole gate between an arbitrary caller-supplied query and a
    real BigQuery API call (see the design notes --
    "Security / read-only enforcement"). A real parser is used instead of
    regex-based comment/string-literal handling because two independent regex
    passes (one for comments, one for string literals) are each blind to the
    other's syntax, letting a comment hide a string boundary or vice versa --
    see `_FORBIDDEN_STATEMENT_TYPES` below.
    """
    if not isinstance(value, str):
        raise ValueError("Query must be a string")

    if len(value) > _MAX_QUERY_LENGTH:
        raise ValueError(f"Query exceeds maximum length of {_MAX_QUERY_LENGTH} characters")

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Query cannot be empty")

    try:
        statements = [s for s in sqlglot.parse(trimmed, read=_SQL_DIALECT) if s is not None]
    except (SqlglotError, RecursionError) as exc:
        raise ValueError("Query could not be parsed as valid SQL") from exc

    if len(statements) != 1:
        raise ValueError("Query must be a single statement -- chained statements are not allowed")

    statement = statements[0]
    # `exp.Query` is the shared base of `exp.Select` and set operations
    # (`exp.Union`/`INTERSECT`/`EXCEPT`) -- a plain `exp.Select` check would
    # wrongly reject legitimate `SELECT ... UNION ALL SELECT ...` queries.
    if not isinstance(statement, exp.Query):
        raise ValueError("Query must start with SELECT or WITH -- DML/DDL is not allowed")

    if list(statement.find_all(*_FORBIDDEN_STATEMENT_TYPES)):
        raise ValueError("Query contains a forbidden keyword -- only read-only SELECT/WITH queries are allowed")

    return trimmed


def _validate_id(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")

    if not value or not value.strip():
        raise ValueError(f"{label} cannot be empty")

    if len(value) > _MAX_ID_LENGTH:
        raise ValueError(f"{label} exceeds maximum length of {_MAX_ID_LENGTH} characters")

    if not _ID_PATTERN.fullmatch(value):
        raise ValueError(
            f"Invalid {label.lower()} format. Must contain only letters, numbers, "
            "and underscores."
        )

    return value


def sanitize_error_message(exc: Exception) -> str:
    """Build a client-safe error message from an exception.

    Redacts any `/path/to/*.json`-shaped substring (a credentials file path)
    from the exception's own message before it reaches the MCP client.
    Mirrors the reference implementation's `createErrorMessage`'s regex (`/\\/[^\\s]+\\.json/g`) -- only
    file paths that look like credentials are redacted; dataset/table/job IDs
    and other identifiers are left intact so real errors stay diagnosable.
    """
    return _CREDENTIALS_FILE_PATTERN.sub("[credentials file]", str(exc))


def redact_credentials_from_text(text: str) -> str:
    """Redact credentials file paths from a text string.

    Applies the same credentials-file-path regex (`_CREDENTIALS_FILE_PATTERN`)
    as `sanitize_error_message` but directly to a string, without going through
    exception stringification. Used by `_reraise_sanitized` to sanitize
    `exc.message` directly for `GoogleAPICallError` subclasses (which would
    otherwise double-prefix the error code when `str(exc)` is called again).
    """
    return _CREDENTIALS_FILE_PATTERN.sub("[credentials file]", text)
