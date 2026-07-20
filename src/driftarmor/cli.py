"""CLI entrypoint: driftarmor check|drift --plan PATH|--dir PATH [--json] [--no-color]."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from driftarmor import __version__
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
from driftarmor.terraform_plan import TerraformError, materialize_plan_json


UNSUPPORTED = """Unsupported:
  - Remote-only modules not present in the plan
  - Live cloud / kubectl inspection (drift is plan JSON only — not live inventory)
  - Unmanaged / shadow resources outside Terraform state
  - Auto-remediation
  - Cost / SKU sizing evaluation
  - Azure resources outside active packs (AKS, SQL, SQL MI, Storage, Managed Redis, Key Vault, ACR, Service Bus, VM, NSG, Front Door)
  - Extra terraform plan flags (-var-file, -target, …) — run plan yourself and pass --plan

Requires terraform on PATH when using --dir or a binary --plan file.
`--dir` runs `terraform init` then `plan` then `show -json`.

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
            "no AKS / SQL / SQL MI / Storage / Managed Redis / Key Vault / "
            "ACR / Service Bus / VM / NSG / Front Door "
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


def _add_plan_source_args(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--plan",
        type=Path,
        help=(
            "Path to terraform show -json output, or a binary plan file "
            "(-out=…) which will be converted via terraform show -json"
        ),
    )
    source.add_argument(
        "--dir",
        type=Path,
        dest="module_dir",
        help=(
            "Terraform module directory: run terraform init, plan -out, "
            "then show -json (terraform must be on PATH)"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="driftarmor",
        description=(
            "Azure Terraform plan implement coach "
            "(AKS / SQL / SQL MI / Storage / Managed Redis / Key Vault / ACR / "
            "Service Bus / VM / NSG / Front Door) + "
            "plan resource_changes destructive-change gate (drift)"
        ),
        epilog=UNSUPPORTED,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    # required=False so -v/--version works without a subcommand
    sub = parser.add_subparsers(dest="command", required=False)

    check = sub.add_parser(
        "check",
        help=(
            "Evaluate a terraform plan for AKS, SQL, SQL MI, "
            "Storage, Managed Redis, Key Vault, ACR, Service Bus, VM, NSG, and Front Door"
        ),
        epilog=UNSUPPORTED,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_plan_source_args(check)
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
    _add_plan_source_args(drift)
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
    if args.command in ("check", "drift"):
        try:
            with materialize_plan_json(
                plan=getattr(args, "plan", None),
                module_dir=getattr(args, "module_dir", None),
            ) as plan_path:
                if args.command == "check":
                    return check_command(
                        plan_path,
                        as_json=args.as_json,
                        no_color=args.no_color,
                    )
                return drift_command(
                    plan_path,
                    as_json=args.as_json,
                    no_color=args.no_color,
                )
        except TerraformError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return 2
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
