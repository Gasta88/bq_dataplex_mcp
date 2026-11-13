"""Tests for app/validation.py: validate_dataset_id/validate_table_id/
validate_sql_query/sanitize_error_message.
"""

from __future__ import annotations

import pytest

from app.validation import (
    sanitize_error_message,
    validate_dataset_id,
    validate_sql_query,
    validate_table_id,
)


# ---------------------------------------------------------------------------
# validate_dataset_id / validate_table_id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("validator", [validate_dataset_id, validate_table_id])
def test_accepts_valid_alphanumeric_underscore_id(validator):
    assert validator("my_dataset_1") == "my_dataset_1"


@pytest.mark.parametrize("validator", [validate_dataset_id, validate_table_id])
@pytest.mark.parametrize("bad_value", [None, 123, "", "   "])
def test_rejects_non_string_or_empty_values(validator, bad_value):
    with pytest.raises(ValueError):
        validator(bad_value)


@pytest.mark.parametrize("validator", [validate_dataset_id, validate_table_id])
def test_rejects_id_exceeding_max_length(validator):
    with pytest.raises(ValueError):
        validator("a" * 1025)


@pytest.mark.parametrize("validator", [validate_dataset_id, validate_table_id])
def test_accepts_id_at_max_length(validator):
    max_len_id = "a" * 1024
    assert validator(max_len_id) == max_len_id


@pytest.mark.parametrize("validator", [validate_dataset_id, validate_table_id])
@pytest.mark.parametrize(
    "bad_value",
    ["my-dataset", "my.dataset", "my dataset", '"; DROP TABLE x; --'],
)
def test_rejects_ids_with_disallowed_characters(validator, bad_value):
    with pytest.raises(ValueError):
        validator(bad_value)


def test_validate_dataset_id_error_message_is_dataset_specific():
    with pytest.raises(ValueError, match="Dataset ID"):
        validate_dataset_id(None)


def test_validate_table_id_error_message_is_table_specific():
    with pytest.raises(ValueError, match="Table ID"):
        validate_table_id(None)


@pytest.mark.parametrize("validator", [validate_dataset_id, validate_table_id])
def test_rejects_ids_with_trailing_newline(validator):
    """Regression test for: Python's `$` in regex matches before final `\n`.
    fullmatch() prevents this; previously match() + anchored pattern accepted
    "valid_id\n" as valid (breaking parity with the reference regex)."""
    with pytest.raises(ValueError):
        validator("valid_id\n")


# ---------------------------------------------------------------------------
# validate_sql_query
# ---------------------------------------------------------------------------


def test_validate_sql_query_accepts_simple_select():
    assert validate_sql_query("SELECT * FROM t") == "SELECT * FROM t"


def test_validate_sql_query_accepts_lowercase_select_with_surrounding_whitespace():
    assert validate_sql_query("  select * from t  ") == "select * from t"


def test_validate_sql_query_accepts_with_clause():
    query = "WITH x AS (SELECT 1) SELECT * FROM x"
    assert validate_sql_query(query) == query


@pytest.mark.parametrize("bad_value", [None, 123, 1.5, [], {}])
def test_validate_sql_query_rejects_non_string(bad_value):
    with pytest.raises(ValueError):
        validate_sql_query(bad_value)


@pytest.mark.parametrize("bad_value", ["", "   ", "\n\t"])
def test_validate_sql_query_rejects_empty_or_whitespace_only(bad_value):
    with pytest.raises(ValueError):
        validate_sql_query(bad_value)


def test_validate_sql_query_rejects_string_exceeding_max_length():
    query = "SELECT * FROM t WHERE x = '" + ("a" * 1_000_000) + "'"
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_accepts_string_at_max_length():
    # Build a query exactly _MAX_QUERY_LENGTH characters long.
    prefix = "SELECT '"
    suffix = "'"
    padding_len = 1_000_000 - len(prefix) - len(suffix)
    query = prefix + ("a" * padding_len) + suffix
    assert len(query) == 1_000_000
    assert validate_sql_query(query) == query


@pytest.mark.parametrize(
    "bad_value",
    ["DELETE FROM t", "UPDATE t SET x=1", "INSERT INTO t VALUES (1)", "DROP TABLE t"],
)
def test_validate_sql_query_rejects_query_not_starting_with_select_or_with(bad_value):
    with pytest.raises(ValueError):
        validate_sql_query(bad_value)


@pytest.mark.parametrize(
    "keyword",
    [
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "CREATE",
        "DROP",
        "TRUNCATE",
        "ALTER",
        "GRANT",
        "REVOKE",
        "REPLACE",
        "EXPORT",
        "LOAD",
        "CALL",
    ],
)
def test_validate_sql_query_rejects_forbidden_keyword_anywhere_in_body(keyword):
    query = f"SELECT 1; {keyword} something"
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_rejects_forbidden_keyword_after_leading_select():
    with pytest.raises(ValueError):
        validate_sql_query("SELECT 1; DROP TABLE t")


def test_validate_sql_query_rejects_forbidden_keyword_smuggled_after_line_comment_newline():
    # The `--` comment only strips to end of line -- a forbidden keyword on
    # the *next* line must still be caught, not silently swallowed.
    query = "SELECT 1 -- a harmless comment\nDROP TABLE t"
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_allows_forbidden_keyword_truly_inside_a_block_comment():
    # A keyword genuinely inside a /* */ block comment is real commented-out
    # text (BigQuery itself would also ignore it) -- not a chained statement.
    query = "SELECT 1 /* DROP TABLE t */ FROM t"
    assert validate_sql_query(query) == query


def test_validate_sql_query_rejects_keyword_hidden_by_nested_line_comment_marker_in_block_comment():
    # A `--` inside a /* */ block comment must not be stripped first -- doing
    # so would truncate the block comment early and hide a real chained
    # statement from the keyword scan (BigQuery still executes it as written).
    query = "SELECT 1/*--*/;DELETE FROM t WHERE TRUE"
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_rejects_keyword_hidden_by_comment_markers_inside_string_literals():
    # `/*` and `*/` placed inside separate string literals must not be read as
    # a real block comment spanning between them -- doing so would collapse a
    # chained DROP into an invisible "comment" while BigQuery still executes
    # the query exactly as written (multiple real statements).
    query = "SELECT '/*' ; DROP TABLE t ; SELECT '*/'"
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_rejects_keyword_hidden_by_quote_inside_a_comment():
    # A `'` living inside a real comment must not be read as a string opener
    # spanning into the next comment -- doing so would collapse a chained
    # DROP into an invisible "string literal" while BigQuery still executes
    # the query exactly as written (multiple real statements). This is the
    # mirror-image of hiding a comment marker inside a string literal.
    query = "SELECT 1 /* ' */ ; DROP TABLE t /* ' */"
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_rejects_query_that_fails_to_parse():
    with pytest.raises(ValueError):
        validate_sql_query("this is not valid sql at all !!!")


def test_validate_sql_query_rejects_select_into():
    # `SELECT ... INTO <target>` assigns a scripting variable rather than
    # returning rows -- reject as defense-in-depth even though BigQuery's
    # Jobs API itself already rejects it as a standalone (non-script) query.
    with pytest.raises(ValueError):
        validate_sql_query("SELECT 1 INTO x")


def test_validate_sql_query_accepts_union_all_query():
    # A set operation (UNION/INTERSECT/EXCEPT) parses to `exp.Union`, a
    # sibling of `exp.Select` under the shared `exp.Query` base -- must not be
    # rejected as if it were DML/DDL.
    query = "SELECT a FROM t UNION ALL SELECT a FROM u"
    assert validate_sql_query(query) == query


def test_validate_sql_query_rejects_forbidden_statement_smuggled_in_a_union_branch():
    query = "SELECT 1 UNION ALL (WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x)"
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_rejects_unterminated_string_literal_as_clean_value_error():
    # sqlglot raises `TokenError` (not `ParseError`) for lexer-level failures
    # like an unterminated string -- both must be caught and turned into the
    # same sanitized ValueError, not leak out as an unexpected exception type.
    with pytest.raises(ValueError):
        validate_sql_query("SELECT '")


def test_validate_sql_query_rejects_deeply_nested_parens_as_clean_value_error():
    # Deeply nested parentheses can blow sqlglot's recursive-descent parser's
    # stack (`RecursionError`) well under the query length cap -- this must
    # degrade to the same clean ValueError, not an uncaught RecursionError.
    query = "SELECT " + "(" * 5000 + "1" + ")" * 5000
    with pytest.raises(ValueError):
        validate_sql_query(query)


def test_validate_sql_query_accepts_semicolon_inside_a_string_literal():
    # A `;` inside a string literal is not a statement separator -- it must
    # not trip the chained-statement guard.
    query = "SELECT ';'"
    assert validate_sql_query(query) == query


def test_validate_sql_query_accepts_string_literal_containing_letters_a_semicolon_and_b():
    query = "SELECT 'a;b' FROM t"
    assert validate_sql_query(query) == query


def test_validate_sql_query_rejects_two_statements_separated_by_semicolon():
    with pytest.raises(ValueError):
        validate_sql_query("SELECT 1; SELECT 2")


def test_validate_sql_query_accepts_single_trailing_semicolon():
    assert validate_sql_query("SELECT 1;") == "SELECT 1;"


def test_validate_sql_query_rejects_two_statements_with_trailing_semicolon():
    with pytest.raises(ValueError):
        validate_sql_query("SELECT 1; SELECT 2;")


def test_validate_sql_query_rejects_comment_and_whitespace_only_query():
    with pytest.raises(ValueError):
        validate_sql_query("-- just a comment\n")


# ---------------------------------------------------------------------------
# sanitize_error_message
# ---------------------------------------------------------------------------


def test_sanitize_error_message_redacts_credentials_file_path():
    exc = Exception("failed to load /Users/foo/creds.json: permission denied")
    assert sanitize_error_message(exc) == "failed to load [credentials file]: permission denied"


def test_sanitize_error_message_passes_through_when_no_path_like_substring():
    exc = Exception("dataset analytics not found")
    assert sanitize_error_message(exc) == "dataset analytics not found"


def test_sanitize_error_message_does_not_redact_non_json_paths():
    exc = Exception("read /Users/foo/data.csv failed")
    assert sanitize_error_message(exc) == "read /Users/foo/data.csv failed"
