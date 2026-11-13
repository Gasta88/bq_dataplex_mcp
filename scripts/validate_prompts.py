#!/usr/bin/env python3
"""Ad hoc invocation-clarity check for the MCP tool descriptions.

Extracts the seven tool docstrings from `app/main.py` via `ast`, builds a system
prompt listing them, sends one real Anthropic Messages API call per prompt in
`tests/eval_prompts.yaml`, and reports per-prompt accuracy plus misfires. The
run writes `tests/eval_results.json` for the operator to inspect.

This is not a pytest test and is not wired into CI. Install the optional
dependencies and set an API key before running:

    pip install anthropic pyyaml
    export ANTHROPIC_API_KEY=...
    python scripts/validate_prompts.py

The check is informal: no fixed accuracy threshold is enforced and the script
does not exit non-zero on a low score.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import yaml

try:
    from anthropic import Anthropic
except ImportError:
    print(
        "ERROR: the `anthropic` package is not installed. This script is an ad hoc,\n"
        "manually-run sanity check -- it is deliberately NOT a pinned dependency in\n"
        "requirements.txt/requirements-dev.txt. Install it yourself before running:\n\n"
        "    pip install anthropic\n",
        file=sys.stderr,
    )
    sys.exit(1)

# The seven MCP tools registered in app/main.py.
TOOL_NAMES = (
    "ping",
    "list_datasets",
    "list_tables",
    "get_table_metadata",
    "get_data_lineage",
    "get_data_quality_results",
    "execute_sql",
)

REPO_ROOT = Path(__file__).parent.parent


def load_eval_prompts() -> list[dict]:
    eval_path = REPO_ROOT / "tests" / "eval_prompts.yaml"
    with open(eval_path) as f:
        eval_data = yaml.safe_load(f)
    return eval_data["prompts"]


def load_tool_docstrings() -> dict[str, str]:
    """Extracts the seven tools' docstrings from app/main.py via `ast`, not a
    regex scrape -- robust against docstring content containing characters
    that would need escaping in a regex (backticks, parens, etc., all of
    which the  hardened docstrings use freely).
    """
    main_py = REPO_ROOT / "app" / "main.py"
    tree = ast.parse(main_py.read_text())

    tools_info: dict[str, str] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef)
            and node.name in TOOL_NAMES
            and (doc := ast.get_docstring(node)) is not None
        ):
            tools_info[node.name] = doc

    missing = set(TOOL_NAMES) - tools_info.keys()
    if missing:
        print(
            f"ERROR: could not find docstrings for {sorted(missing)} in app/main.py "
            "-- check TOOL_NAMES / the file's own function names.",
            file=sys.stderr,
        )
        sys.exit(1)
    return tools_info


def build_system_prompt(tools_info: dict[str, str]) -> str:
    docstring_ref = "\n\n".join(
        f"**{tool}:**\n{docstring}" for tool, docstring in sorted(tools_info.items())
    )
    return f"""You are evaluating whether a user prompt would lead an LLM to select the correct
tool for a BigQuery/Dataplex data-platform MCP server. You have the following tools
available:

{docstring_ref}

For each user prompt, determine which tool the LLM should select based on the docstrings
above. Respond with ONLY the tool name (e.g., "list_tables"), nothing else.
If the prompt is genuinely ambiguous and could map to 2+ tools, list them separated by
" | " (e.g., "get_table_metadata | get_data_lineage").
"""


def main() -> int:
    prompts = load_eval_prompts()
    tools_info = load_tool_docstrings()
    system_prompt = build_system_prompt(tools_info)

    client = Anthropic()

    results: dict = {
        "total": len(prompts),
        "correct": 0,
        "failed": [],
        "edge_cases": [],
        "evaluations": [],
    }

    print(f"Validating {len(prompts)} test prompts...\n")
    print(f"Tools tested: {', '.join(sorted(tools_info.keys()))}\n")

    for i, prompt in enumerate(prompts, 1):
        prompt_id = prompt["id"]
        text = prompt["text"]
        expected = prompt["expected_tool"]

        message = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=50,
            system=system_prompt,
            messages=[{"role": "user", "content": text}],
        )
        selected = message.content[0].text.strip().strip("`'\"")

        # Allow multiple acceptable answers, either side: expected may itself
        # be pipe-separated ("tool_a|tool_b") for a genuinely ambiguous
        # prompt (tests/eval_prompts.yaml's threeway_04), and the model's own
        # answer may list multiple tools it considered.
        expected_options = [t.strip() for t in expected.split("|")]
        selected_options = [t.strip() for t in selected.split("|")]
        is_correct = (
            (selected_options == expected_options)
            if len(expected_options) == 1
            else any(opt in selected_options for opt in expected_options)
        )

        evaluation = {
            "id": prompt_id,
            "text": text,
            "expected": expected,
            "selected": selected,
            "correct": is_correct,
            "category": prompt["category"],
            "rationale": prompt["rationale"],
        }
        results["evaluations"].append(evaluation)

        if is_correct:
            results["correct"] += 1
            status = "PASS"
        else:
            status = "FAIL"
            results["failed"].append(prompt_id)

        if len(selected_options) > 1:
            results["edge_cases"].append(
                {
                    "id": prompt_id,
                    "reason": f"Multiple tools selected: {selected}",
                    "expected": expected,
                }
            )

        print(
            f"[{i:2d}] {status:4s} {prompt_id:16s} | Expected: {expected:55s} | Selected: {selected}"
        )

    accuracy = results["correct"] / results["total"] if results["total"] > 0 else 0
    print(f"\n{'=' * 100}")
    print(f"Accuracy: {results['correct']}/{results['total']} ({100 * accuracy:.1f}%)")
    print(
        "Note: this is an informal, non-gating invocation check ('s own exit "
        "criterion) -- no fixed accuracy target is enforced. "
        " precedent's committed 90% threshold."
    )
    print(f"{'=' * 100}\n")

    if results["failed"]:
        print(f"Failed prompts ({len(results['failed'])}):")
        for prompt_id in results["failed"]:
            for evaluation in results["evaluations"]:
                if evaluation["id"] == prompt_id:
                    print(
                        f"  - {prompt_id}: expected {evaluation['expected']}, got {evaluation['selected']}"
                    )
        print()

    if results["edge_cases"]:
        print(f"Edge cases / multi-tool answers ({len(results['edge_cases'])}):")
        for case in results["edge_cases"]:
            print(f"  - {case['id']}: {case['reason']}")
        print()

    results_file = REPO_ROOT / "tests" / "eval_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {results_file}\n")

    # Informal check -- always exits 0 regardless of accuracy (see module
    # docstring). The operator reads tests/eval_results.json / the printed
    # accuracy figure and pastes it into the PR description as evidence.
    return 0


if __name__ == "__main__":
    sys.exit(main())
