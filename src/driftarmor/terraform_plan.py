"""Invoke Terraform to produce plan JSON for DriftArmor check/drift."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class TerraformError(Exception):
    """Terraform missing, failed, or could not produce plan JSON."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def find_terraform() -> Path:
    """Return path to the terraform executable or raise TerraformError."""
    found = shutil.which("terraform")
    if not found:
        raise TerraformError(
            "terraform not found on PATH "
            "(required for --dir or a binary --plan file)"
        )
    return Path(found)


def is_plan_json(path: Path) -> bool:
    """True if path is a readable UTF-8 JSON object (show -json shape)."""
    if not path.is_file():
        return False
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(data, dict)


def looks_like_json_text(path: Path) -> bool:
    """True if the file appears to be textual JSON (even if invalid)."""
    if not path.is_file():
        return False
    try:
        head = path.read_bytes()[:64].lstrip()
    except OSError:
        return False
    return head.startswith(b"{") or head.startswith(b"[")


def _write_stream(text: str) -> None:
    if not text:
        return
    sys.stderr.write(text)
    if not text.endswith("\n"):
        sys.stderr.write("\n")


def show_plan_json(
    plan_file: Path,
    *,
    dest_dir: Path,
    workdir: Path | None = None,
) -> Path:
    """Run ``terraform show -json`` and write stdout to dest_dir/plan.json."""
    terraform = find_terraform()
    plan_file = plan_file.resolve()
    if not plan_file.is_file():
        raise TerraformError(f"plan file not found: {plan_file}")

    out_path = dest_dir / "plan.json"
    cmd = [str(terraform), "show", "-json", str(plan_file)]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workdir) if workdir is not None else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise TerraformError(f"failed to run terraform show: {exc}") from exc

    _write_stream(proc.stderr)

    if proc.returncode != 0:
        raise TerraformError(
            f"terraform show -json failed (exit {proc.returncode})"
        )

    try:
        out_path.write_text(proc.stdout, encoding="utf-8")
    except OSError as exc:
        raise TerraformError(f"cannot write plan JSON: {exc}") from exc

    if not is_plan_json(out_path):
        raise TerraformError("terraform show -json did not produce a JSON object")

    return out_path


def run_init(workdir: Path) -> None:
    """Run ``terraform init -input=false`` in workdir."""
    terraform = find_terraform()
    workdir = workdir.resolve()
    if not workdir.is_dir():
        raise TerraformError(f"terraform module directory not found: {workdir}")

    cmd = [
        str(terraform),
        "init",
        "-input=false",
        "-no-color",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise TerraformError(f"failed to run terraform init: {exc}") from exc

    _write_stream(proc.stderr)
    _write_stream(proc.stdout)

    if proc.returncode != 0:
        raise TerraformError(
            f"terraform init failed (exit {proc.returncode})"
        )


def run_plan(workdir: Path, *, dest_dir: Path) -> Path:
    """Run ``terraform init``, ``plan -out``, then ``show -json`` in workdir."""
    terraform = find_terraform()
    workdir = workdir.resolve()
    if not workdir.is_dir():
        raise TerraformError(f"terraform module directory not found: {workdir}")

    run_init(workdir)

    binary_path = dest_dir / "tfplan"
    cmd = [
        str(terraform),
        "plan",
        f"-out={binary_path}",
        "-input=false",
        "-no-color",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise TerraformError(f"failed to run terraform plan: {exc}") from exc

    # Terraform plan diagnostics / progress — keep visible on stderr.
    _write_stream(proc.stderr)
    _write_stream(proc.stdout)

    if proc.returncode != 0:
        raise TerraformError(
            f"terraform plan failed (exit {proc.returncode})"
        )

    return show_plan_json(binary_path, dest_dir=dest_dir, workdir=workdir)


@contextmanager
def materialize_plan_json(
    *,
    plan: Path | None = None,
    module_dir: Path | None = None,
) -> Iterator[Path]:
    """Yield a path to plan JSON; clean up temps when done.

    Exactly one of ``plan`` or ``module_dir`` must be set.
    """
    if (plan is None) == (module_dir is None):
        raise TerraformError("provide exactly one of --plan or --dir")

    if plan is not None:
        plan = plan.expanduser()
        if not plan.is_file():
            raise TerraformError(f"plan file not found: {plan}")
        # Valid JSON, or textual JSON that should fail in load_plan_json —
        # never send those through `terraform show`.
        if is_plan_json(plan) or looks_like_json_text(plan):
            yield plan
            return
        with tempfile.TemporaryDirectory(prefix="driftarmor-plan-") as tmp:
            yield show_plan_json(plan, dest_dir=Path(tmp), workdir=plan.parent)
        return

    assert module_dir is not None
    module_dir = module_dir.expanduser()
    with tempfile.TemporaryDirectory(prefix="driftarmor-plan-") as tmp:
        yield run_plan(module_dir, dest_dir=Path(tmp))
