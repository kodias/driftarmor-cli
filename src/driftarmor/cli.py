"""CLI entrypoint: driftarmor check|drift --plan PATH [--json] [--no-color]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from driftarmor.checkov_runner import CheckovNotFoundError, CheckovRunError, run_checkov
from driftarmor.color import ACTION_TO_LEVEL, SEVERITY_TO_LEVEL, colorize, colors_enabled
from driftarmor.drift import (
    UnknownActionsError,
    build_drift_report,
    exit_code_for_drift,
)
from driftarmor.packs import detect_packs
from driftarmor.plan_io import PlanLoadError, load_plan_json
from driftarmor.report import empty_report, exit_code_for_report, map_checkov_to_report


UNSUPPORTED = """Unsupported:
  - Plain .tf without plan JSON (use: terraform show -json <planfile>)
  - Remote-only modules not present in the plan
  - Live cloud / kubectl inspection (drift is plan JSON only — not live inventory)
  - Unmanaged / shadow resources outside Terraform state
  - Auto-remediation
  - Cost / SKU sizing evaluation
  - Azure resources outside active packs (AKS, SQL, SQL MI, Storage, Key Vault, ACR, Service Bus, VM, NSG, Front Door)

drift = destructive-change gate on terraform show -json resource_changes
  (exit 1 on delete/replace). Not continuous live drift detection.
"""


def _product_sections(report: dict[str, Any]) -> list[dict[str, Any]]:
    products = report.get("products")
    if isinstance(products, list) and products:
        return products
    # Legacy flat reports: one anonymous section
    return [
        {
            "id": "",
            "title": "",
            "results": report.get("results") or [],
        }
    ]


def _print_check_human(
    report: dict[str, Any],
    *,
    nothing_to_check: bool = False,
    enabled: bool = False,
) -> None:
    if nothing_to_check:
        print(
            "no AKS / SQL / SQL MI / Storage / Key Vault / ACR / Service Bus / "
            "VM / NSG / Front Door "
            "resources; nothing to check"
        )
        return
    summary = report.get("summary") or {}
    print(
        "summary  "
        f"pass={summary.get('pass', 0)}  "
        f"fail={summary.get('fail', 0)}  "
        f"warn={summary.get('warn', 0)}  "
        f"manual={summary.get('manual', 0)}"
    )
    for section in _product_sections(report):
        title = section.get("title") or section.get("id") or ""
        if title:
            print()
            print(f"=== {title} ===")
        print()
        print(f"{'SEVERITY':<8}  {'ID':<36}  TITLE")
        print(f"{'-' * 8}  {'-' * 36}  {'-' * 40}")
        for row in section.get("results") or []:
            severity = str(row.get("severity", ""))
            padded = f"{severity:<8}"
            level = SEVERITY_TO_LEVEL.get(severity)
            sev_cell = colorize(padded, level, enabled=enabled) if level else padded
            print(
                f"{sev_cell}  "
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


def _print_drift_human(report: dict[str, Any], *, enabled: bool = False) -> None:
    summary = report.get("summary") or {}
    print(
        "summary  "
        f"create={summary.get('create', 0)}  "
        f"update={summary.get('update', 0)}  "
        f"delete={summary.get('delete', 0)}  "
        f"replace={summary.get('replace', 0)}"
    )
    for section in _product_sections(report):
        title = section.get("title") or section.get("id") or ""
        if title:
            print()
            print(f"=== {title} ===")
        print()
        print(f"{'ACTION':<8}  {'ADDRESS':<44}  TYPE")
        print(f"{'-' * 8}  {'-' * 44}  {'-' * 32}")
        for row in section.get("results") or []:
            action = str(row.get("action_class", ""))
            padded = f"{action:<8}"
            level = ACTION_TO_LEVEL.get(action)
            act_cell = colorize(padded, level, enabled=enabled) if level else padded
            print(
                f"{act_cell}  "
                f"{row.get('address', ''):<44}  "
                f"{row.get('type', '')}"
            )


def check_command(
    plan_path: Path,
    *,
    as_json: bool,
    no_color: bool = False,
) -> int:
    try:
        plan = load_plan_json(plan_path)
    except PlanLoadError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 2

    enabled = False if as_json else colors_enabled(no_color=no_color)

    packs = detect_packs(plan)
    if not packs:
        report = empty_report()
        if as_json:
            print(json.dumps(report, indent=2))
        else:
            _print_check_human(report, nothing_to_check=True, enabled=enabled)
        return 0

    try:
        checkov_report = run_checkov(plan_path, packs=packs)
    except CheckovNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except CheckovRunError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = map_checkov_to_report(checkov_report, plan, packs=packs)
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        _print_check_human(report, enabled=enabled)
    return exit_code_for_report(report)


def drift_command(
    plan_path: Path,
    *,
    as_json: bool,
    no_color: bool = False,
) -> int:
    try:
        plan = load_plan_json(plan_path)
    except PlanLoadError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 2

    try:
        report = build_drift_report(plan)
    except UnknownActionsError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        return 2

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        enabled = colors_enabled(no_color=no_color)
        _print_drift_human(report, enabled=enabled)
    return exit_code_for_drift(report)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driftarmor",
        description=(
            "Azure Terraform plan implement coach "
            "(AKS / SQL / SQL MI / Storage / Key Vault / ACR / Service Bus / "
            "VM / NSG / Front Door) + "
            "plan resource_changes destructive-change gate (drift)"
        ),
        epilog=UNSUPPORTED,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser(
        "check",
        help=(
            "Evaluate a terraform show -json plan for AKS, SQL, SQL MI, "
            "Storage, Key Vault, ACR, Service Bus, VM, NSG, and Front Door"
        ),
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
    check.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        help="Disable ANSI colors in human output",
    )

    drift = sub.add_parser(
        "drift",
        help=(
            "Summarize plan resource_changes (destructive-change gate; "
            "not live cloud drift)"
        ),
        epilog=UNSUPPORTED,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    drift.add_argument(
        "--plan",
        required=True,
        type=Path,
        help="Path to terraform show -json output",
    )
    drift.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit Drift JSON instead of a human table",
    )
    drift.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        help="Disable ANSI colors in human output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "check":
        return check_command(
            args.plan,
            as_json=args.as_json,
            no_color=args.no_color,
        )
    if args.command == "drift":
        return drift_command(
            args.plan,
            as_json=args.as_json,
            no_color=args.no_color,
        )
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
