# DriftArmor CLI

Local implement coach for AKS-centered Terraform plans (`check`), plus a
**destructive-change gate** on plan JSON (`drift`). Wraps **Checkov** custom
policies for `check` and prints citation checklists with exit codes.

Product / marketing site: [driftarmor.net](https://www.driftarmor.net)

> **`drift` is not live cloud drift detection.** It classifies
> `resource_changes` from `terraform show -json` (create/update/delete/replace).
> It does not call Azure/AWS/GCP APIs or find unmanaged resources.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

`checkov` is a package dependency; `pip install -e .` is enough.

## Usage

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

# AKS implement coach (Checkov policies + citations)
driftarmor check --plan plan.json
driftarmor check --plan plan.json --json
driftarmor check --plan plan.json --no-color

# Destructive-change gate on resource_changes (exit 1 on delete/replace)
driftarmor drift --plan plan.json
driftarmor drift --plan plan.json --json
```

Human output uses green / yellow / red on TTY. Colors disable when stdout is
not a TTY, when `NO_COLOR` is set, or with `--no-color`. `--json` never uses ANSI.

Large plan files are loaded fully into memory (same as `check`).

### Exit codes

| Command | 0 | 1 | 2 |
|---------|---|---|---|
| `check` | No AKS resources, or no `fail` | One or more `fail` | Bad plan JSON / checkov missing |
| `drift` | No delete/replace (creates/updates OK) | Any delete or replace | Bad plan JSON / unknown actions |

## Fixtures

```bash
driftarmor check --plan fixtures/aks-plan/fail.json   # exit 1
driftarmor check --plan fixtures/aks-plan/pass.json   # exit 0
driftarmor drift --plan fixtures/drift-plan/replace.json  # exit 1
pytest
```

## Providers

- `check` — AKS Checkov policy pack today  
- `drift` — provider-agnostic plan-diff (any Terraform plan JSON)

## Founder dogfood

Track misses while using this on real plans: [`wedge-miss-list.md`](wedge-miss-list.md).
