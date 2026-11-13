#!/usr/bin/env python3
"""Smoke-test a deployed bq-dataplex-mcp-dev Cloud Run service end-to-end.

Resolves the service URL, starts an authenticated `gcloud run services proxy`,
then exercises all seven MCP tools through `fastmcp.Client`: `ping`,
`list_tools`, the BigQuery metadata tools, lineage, data quality, and
`execute_sql` (real and dry-run). Prints one line per check and exits 0 only
if every check passed.

Scoped to the dev environment: a dev deployment is expected to grant
`roles/run.invoker` to the engineer running this check. No prod invoker grant
is assumed. The project defaults to `GCP_PROJECT` or `example-project` and can
be overridden with `--project`.

Usage:
    python scripts/smoke_test_dev.py
    python scripts/smoke_test_dev.py --project my-project --port 8081
"""

import argparse
import asyncio
import os
import socket
import subprocess
import sys
import time

from fastmcp import Client

PROJECT = os.getenv("GCP_PROJECT", "example-project")
REGION = "us-central1"
SERVICE = "bq-dataplex-mcp-dev"
PROXY_STARTUP_TIMEOUT = 45

EXPECTED_PING_RESULT = {"status": "ok", "service": "bq-dataplex-mcp"}

# The full seven-tool contract: `ping` plus the six BigQuery/Dataplex/lineage
# tools. Catalog-search tools are intentionally out of scope.
EXPECTED_TOOL_NAMES = {
    "ping",
    "list_datasets",
    "list_tables",
    "get_table_metadata",
    "get_data_lineage",
    "get_data_quality_results",
    "execute_sql",
}


def resolve_dev_url() -> str:
    result = subprocess.run(
        [
            "gcloud", "run", "services", "describe", SERVICE,
            f"--project={PROJECT}", f"--region={REGION}",
            "--format=value(status.url)",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        print(f"ERROR: could not resolve the {SERVICE} URL.", file=sys.stderr)
        print("Is it deployed? (cd deploy && make apply ENV=dev)", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def start_proxy(port: int) -> subprocess.Popen:
    """Start `gcloud run services proxy` in the background and wait for it to be ready.

    Only stdin is piped (to auto-accept the one-time cloud-run-proxy component
    install prompt) -- stdout/stderr are left inherited so a long-running proxy
    can never block on a full pipe buffer. Readiness is checked by polling the
    local port directly rather than parsing proxy output.
    """
    proc = subprocess.Popen(
        [
            "gcloud", "run", "services", "proxy", SERVICE,
            f"--region={REGION}", f"--project={PROJECT}", f"--port={port}",
        ],
        stdin=subprocess.PIPE,
        text=True,
    )
    try:
        proc.stdin.write("Y\n")
        proc.stdin.flush()
    except (BrokenPipeError, ValueError):
        pass

    deadline = time.monotonic() + PROXY_STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"gcloud run services proxy exited early with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return proc
        except OSError:
            time.sleep(1)

    proc.terminate()
    raise RuntimeError(
        f"gcloud run services proxy did not come up on port {port} within "
        f"{PROXY_STARTUP_TIMEOUT}s. If this is the first run on this machine, the "
        "'cloud-run-proxy' component install may need an interactive terminal -- "
        "run the proxy command manually once, then retry."
    )


def stop_proxy(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


async def _call(client: Client, name: str, kwargs: dict | None = None) -> dict:
    """Call a tool, time it, and return a result dict without raising.

    Call a tool, time it, and return a result dict without raising.
    """
    kwargs = kwargs or {}
    t0 = time.perf_counter()
    try:
        result = await client.call_tool(name, kwargs)
        ms = (time.perf_counter() - t0) * 1000
        return {"tool": name, "ok": True, "ms": round(ms, 1), "result": result.data}
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000
        return {"tool": name, "ok": False, "ms": round(ms, 1), "error": f"{type(exc).__name__}: {exc}"}


async def run_smoke_test(proxy_base_url: str) -> bool:
    """Exercise all seven tools through the proxy and report pass/fail per tool.

    An empty dev project (no datasets, or a table with no recorded lineage / no
    configured DQ scan) is still a pass for the affected calls -- those are
    documented, tested success branches (empty-diagram / "no scan configured"
    message), not failures. This function returns False only on an actual
    tool/transport failure (a raised exception surfaced by `_call()`, or a
    `list_tools()` name-set mismatch).
    """
    all_ok = True
    async with Client(f"{proxy_base_url}/mcp") as client:
        # 1. ping -- existing baseline check.
        r = await _call(client, "ping")
        print(r)
        all_ok = all_ok and r["ok"] and r.get("result") == EXPECTED_PING_RESULT

        # 2. list_tools() -- discoverability check for all seven tool names.
        t0 = time.perf_counter()
        try:
            tools = await client.list_tools()
            ms = round((time.perf_counter() - t0) * 1000, 1)
            found_names = {tool.name for tool in tools}
            tools_ok = found_names == EXPECTED_TOOL_NAMES
            print({"tool": "list_tools", "ok": tools_ok, "ms": ms, "result": sorted(found_names)})
        except Exception as exc:
            ms = round((time.perf_counter() - t0) * 1000, 1)
            tools_ok = False
            print({"tool": "list_tools", "ok": False, "ms": ms, "error": f"{type(exc).__name__}: {exc}"})
        all_ok = all_ok and tools_ok

        # 3. list_datasets() -> pick first dataset.
        r = await _call(client, "list_datasets")
        print(r)
        all_ok = all_ok and r["ok"]
        datasets = r["result"].get("datasets", []) if r["ok"] else []

        if datasets:
            dataset_id = datasets[0]

            # 4. list_tables(dataset_id) -> pick first table.
            r = await _call(client, "list_tables", {"dataset_id": dataset_id})
            print(r)
            all_ok = all_ok and r["ok"]
            tables = r["result"].get("tables", []) if r["ok"] else []

            if tables:
                table_id = tables[0]
                table_kwargs = {"dataset_id": dataset_id, "table_id": table_id}

                # 5. get_table_metadata / get_data_lineage / get_data_quality_results
                # chained on the first discovered (dataset_id, table_id) pair.
                for name in (
                    "get_table_metadata",
                    "get_data_lineage",
                    "get_data_quality_results",
                ):
                    r = await _call(client, name, table_kwargs)
                    print(r)
                    all_ok = all_ok and r["ok"]
            else:
                print(
                    f"no tables in dataset {dataset_id!r} -- skipping "
                    "get_table_metadata/get_data_lineage/get_data_quality_results checks"
                )
        else:
            print("no datasets -- skipping list_tables/metadata/lineage/quality checks")

        # 6. execute_sql("SELECT 1") -- real run, 0 bytes processed.
        r = await _call(client, "execute_sql", {"query": "SELECT 1"})
        print(r)
        all_ok = all_ok and r["ok"]

        # 7. execute_sql("SELECT 1", dry_run=True) -- proves the byte-cap/estimate
        # path without any billing.
        r = await _call(client, "execute_sql", {"query": "SELECT 1", "dry_run": True})
        print(r)
        all_ok = all_ok and r["ok"]

    return all_ok


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--project", default=PROJECT,
        help=f"GCP project containing the dev service (default: {PROJECT}).",
    )
    parser.add_argument(
        "--port", type=int, default=8081,
        help="Local port for the authenticated proxy (default: 8081).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    global PROJECT
    PROJECT = args.project
    url = resolve_dev_url()
    print(f"Target: {url}")

    print(f"Starting authenticated proxy on 127.0.0.1:{args.port} ...")
    proxy = start_proxy(args.port)
    proxy_base_url = f"http://127.0.0.1:{args.port}"
    try:
        ok = asyncio.run(run_smoke_test(proxy_base_url))
    finally:
        print("Stopping proxy...")
        stop_proxy(proxy)

    if ok:
        print("\n✅ Smoke test passed — all 7 tool checks completed successfully.")
        return 0
    print("\n❌ Smoke test failed — see errors above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
