#!/usr/bin/env python3
"""Manual check for `execute_sql` byte-cap enforcement and reservation routing.

Calls the `execute_sql` tool in-process three times with a caller-supplied
query:

    1. `dry_run=True` -- prints bytes processed and the cost estimate without
       billing.
    2. A real run with a deliberately tiny `max_bytes_billed` (100 bytes) --
       expected to fail cleanly with a BigQuery cost-cap error.
    3. A real run with the default 100 GiB cap -- expected to succeed; prints
       the job ID so the reservation routing can be cross-checked with
       `bq show --format=prettyjson -j <jobId>`.

Item 3 bills a small amount, so this is not wired into CI. Requires Application
Default Credentials with BigQuery read and job-user access. Set
`BIGQUERY_RESERVATION` to verify routing onto a flat-rate reservation.

Usage:
    gcloud auth application-default login
    export GCP_PROJECT=my-project
    python scripts/verify_execute_sql_byte_cap_and_reservation.py \
        --query "SELECT * FROM `my-project.my_dataset.my_table` LIMIT 10"
"""

from __future__ import annotations

import argparse
import json
import sys

# Deliberately tiny -- smaller than any real query could ever satisfy, so
# BigQuery rejects the job before it runs (100 bytes).
TINY_MAX_BYTES_BILLED = "100"


def _print_result(label: str, args: dict, result: object) -> None:
    print(f"=== {label}: execute_sql({json.dumps(args)}) ===")
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    print()


def run_verification(query: str) -> int:
    # Imported lazily so `--help` works without GCP credentials configured,
    # and so importing this module for its constants never triggers ADC
    # resolution (mirrors app/main.py's own lazy-BigQueryClient rationale).
    from app.main import execute_sql

    exit_code = 0

    # --- 1. Dry run: estimate cost without billing -------------------------
    print("--- Step 1: dry run (estimate cost, no billing) ---")
    try:
        dry_result = execute_sql(query, dry_run=True)
        _print_result("dry_run=True", {"query": query, "dry_run": True}, dry_result)
        assert dry_result["dryRun"] is True
        print("PASS: dry run estimated cost without running/billing the query.\n")
    except Exception as exc:  # noqa: BLE001 -- print whatever surfaces, don't hide it
        print(f"UNEXPECTED FAILURE on dry run: {exc}\n")
        exit_code = 1

    # --- 2. Real run, deliberately tiny max_bytes_billed --------------------
    print(f"--- Step 2: real run with max_bytes_billed={TINY_MAX_BYTES_BILLED!r} (expect a clean cap failure) ---")
    try:
        over_budget_result = execute_sql(
            query, dry_run=False, max_bytes_billed=TINY_MAX_BYTES_BILLED
        )
        print(
            "UNEXPECTED: query succeeded despite a 100-byte cap -- byte cap is NOT "
            f"being enforced. Result: {json.dumps(over_budget_result, default=str)}\n"
        )
        exit_code = 1
    except Exception as exc:  # noqa: BLE001 -- this is the *expected* path
        print(f"PASS: query rejected cleanly for exceeding max_bytes_billed: {exc}\n")

    # --- 3. Real run, default 100 GiB cap ------------------------------------
    print("--- Step 3: real run with the default 100 GiB cap (expect success) ---")
    try:
        real_result = execute_sql(query, dry_run=False)
        _print_result("dry_run=False (default cap)", {"query": query}, real_result)
        job_id = real_result.get("jobId")
        print(
            f"PASS: query succeeded. jobId={job_id!r} -- cross-check reservation routing via:\n"
            f"    bq show --format=prettyjson -j {job_id}\n"
            "  (look for `configuration.query.reservation` /"
            " `statistics.reservation_id` / `statistics.query.jobConfigurationQuery"
            ".reservationUsage` fields, or the BigQuery console job details page)\n"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"UNEXPECTED FAILURE on default-cap real run: {exc}\n")
        exit_code = 1

    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--query",
        required=True,
        help="SELECT/WITH query to use for all three steps. Pick a small table; "
        "step 3 runs the query for real and bills for the bytes it scans.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run_verification(args.query)


if __name__ == "__main__":
    sys.exit(main())
