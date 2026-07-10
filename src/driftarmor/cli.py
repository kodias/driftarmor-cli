"""CLI entrypoint: driftarmor check --plan PATH [--json]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from driftarmor.aks import has_aks_resources
from driftarmor.checkov_runner import CheckovNotFoundError, CheckovRunError, run_checkov
from driftarmor.report import empty_report, exit_code_for_report, map_checkov_to_report


UNSUPPORTED = """Unsupported in v0:
  - Plain .tf without plan JSON (use: terraform show -json <planfile>)
  - Remote-only modules not present in the plan
  - Live Azure / kubectl inspection
  - Auto-remediation
  - Cost / SKU sizing evaluation
"""


def _print_human(report: dict[str, Any], *, nothing_to_check: bool = False) -> None:
    if nothing_to_check:
        print("no AKS resources; nothing to check")
        return
    summary = report.get("summary") or {}
    print(
        "summary  "
        f"pass={summary.get('pass', 0)}  "
        f"fail={summary.get('fail', 0)}  "
        f"warn={summary.get('warn', 0)}  "
        f"manual={summary.get('manual', 0)}"
    )
    print()
    print(f"{'SEVERITY':<8}  {'ID':<36}  TITLE")
    print(f"{'-' * 8}  {'-' * 36}  {'-' * 40}")
    for row in report.get("results") or []:
        print(
            f"{row.get('severity', ''):<8}  "
            f"{row.get('id', ''):<36}  "
            f"{row.get('title', '')}"
        )
        detail = row.get("detail") or ""
        cite = row.get("citation_url") or ""
        if detail:
            print(f"          {detail}")
        if cite:
            print(f"          cite: {cite}")
        print()


def check_command(plan_path: Path, *, as_json: bool) -> int:
    if not plan_path.is_file():
        print(f"error: plan file not found: {plan_path}", file=sys.stderr)
        return 2

    try:
        raw = plan_path.read_text(encoding="utf-8")
        plan = json.loads(raw)
    except OSError as exc:
        print(f"error: cannot read plan: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid plan JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(plan, dict):
        print("error: plan JSON root must be an object", file=sys.stderr)
        return 2

    if not has_aks_resources(plan):
        report = empty_report()
        if as_json:
            print(json.dumps(report, indent=2))
        else:
            _print_human(report, nothing_to_check=True)
        return 0

    try:
        checkov_report = run_checkov(plan_path)
    except CheckovNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except CheckovRunError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = map_checkov_to_report(checkov_report, plan)
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)
    return exit_code_for_report(report)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driftarmor",
        description="Checkov-backed AKS Terraform plan implement coach",
        epilog=UNSUPPORTED,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check",
        help="Evaluate a terraform show -json plan for AKS defaults",
        epilog=UNSUPPORTED,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check.add_argument(
        "--plan",
        required=True,
        type=Path,
        help="Path to terraform show -json output",
    )
    check.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit Report JSON instead of a human table",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "check":
        return check_command(args.plan, as_json=args.as_json)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
