# DriftArmor CLI

Local implement coach for AKS-centered Terraform plans. Wraps **Checkov** custom policies and prints a citation checklist with exit codes.

Product / marketing site: [driftarmor.net](https://www.driftarmor.net)

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
driftarmor check --plan plan.json
driftarmor check --plan plan.json --json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No AKS resources, or no `fail` results (warn/manual allowed) |
| 1 | One or more `fail` |
| 2 | Missing/invalid plan JSON, or checkov unavailable |

## Fixtures

See [`fixtures/aks-plan/README.md`](fixtures/aks-plan/README.md).

```bash
driftarmor check --plan fixtures/aks-plan/fail.json   # exit 1
driftarmor check --plan fixtures/aks-plan/pass.json   # exit 0
pytest
```

## Founder dogfood

Track misses while using this on real plans: [`wedge-miss-list.md`](wedge-miss-list.md).
