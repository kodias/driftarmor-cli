# DriftArmor CLI

Local implement coach for Azure Terraform plans (`check`), plus a
**destructive-change gate** on plan JSON (`drift`). Wraps **Checkov** custom
policies for `check` and prints citation checklists with exit codes.

Active `check` packs (report order): **AKS** → **Azure SQL** → **Storage** → **VM** → **NSG**.
`drift` groups the same way (plus **Other** for unmatched types).

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

# Implement coach (Checkov packs + citations) — AKS / SQL / Storage / VM / NSG
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
| `check` | No matched packs, or no `fail` | One or more `fail` | Bad plan JSON / checkov missing |
| `drift` | No delete/replace (creates/updates OK) | Any delete or replace | Bad plan JSON / unknown actions |

## Fixtures

```bash
driftarmor check --plan fixtures/aks-plan/fail.json       # exit 1
driftarmor check --plan fixtures/storage-plan/pass.json   # exit 0
driftarmor check --plan fixtures/sql-plan/fail.json       # exit 1
driftarmor check --plan fixtures/vm-plan/fail.json        # exit 1
driftarmor check --plan fixtures/nsg-plan/pass.json       # exit 0
driftarmor drift --plan fixtures/drift-plan/replace.json  # exit 1
pytest
```

## Providers

- `check` — Checkov policy packs (auto-detected from plan resources):
  - **AKS** — `azurerm_kubernetes_cluster` (+ node pools)
  - **Storage** — `azurerm_storage_account` (HTTPS, TLS, public blobs, network)
  - **Azure SQL** — `azurerm_mssql_server` / `_database` / `_firewall_rule`
  - **VM** — `azurerm_linux_virtual_machine` / `azurerm_windows_virtual_machine`
  - **NSG** — `azurerm_network_security_group` / `azurerm_network_security_rule`
- `drift` — provider-agnostic plan-diff (any Terraform plan JSON)

### Virtual Machines (new)

Detected when the plan includes Linux or Windows VMs. Rules:

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `vm.encryption_at_host` | fail | `encryption_at_host_enabled` |
| `vm.trusted_launch` | fail | `secure_boot_enabled` **and** `vtpm_enabled` |
| `vm.linux_password_auth` | fail | Linux only: `disable_password_authentication` |
| `vm.managed_identity` | warn | `identity` block (SystemAssigned / UserAssigned) |

### Network Security Groups (new)

Detected for NSGs and standalone security rules (inline `security_rule` or `azurerm_network_security_rule`). Rules:

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `nsg.open_ssh_internet` | fail | Inbound Allow SSH (22) from `*`, `Internet`, or `0.0.0.0/0` |
| `nsg.open_rdp_internet` | fail | Inbound Allow RDP (3389) from the Internet |
| `nsg.open_all_internet` | fail | Inbound Allow all ports (`*`) from the Internet |

## Founder dogfood

Track misses while using this on real plans: [`wedge-miss-list.md`](wedge-miss-list.md).
