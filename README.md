# DriftArmor CLI

Local implement coach for Azure Terraform plans (`check`), plus a
**destructive-change gate** on plan JSON (`drift`). Wraps **Checkov** custom
policies for `check` and prints citation checklists with exit codes.

Active `check` packs (report order): **AKS** → **Azure SQL** → **SQL Managed Instance** → **Storage** → **Managed Redis** → **Key Vault** → **ACR** → **Service Bus** → **VM** → **NSG** → **Front Door**.
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

# Implement coach (Checkov packs + citations)
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
driftarmor check --plan fixtures/aks-plan/fail.json          # exit 1
driftarmor check --plan fixtures/storage-plan/pass.json      # exit 0
driftarmor check --plan fixtures/sql-plan/fail.json          # exit 1
driftarmor check --plan fixtures/sqlmi-plan/pass.json        # exit 0
driftarmor check --plan fixtures/redis-plan/pass.json        # exit 0
driftarmor check --plan fixtures/keyvault-plan/fail.json     # exit 1
driftarmor check --plan fixtures/acr-plan/pass.json          # exit 0
driftarmor check --plan fixtures/servicebus-plan/fail.json   # exit 1
driftarmor check --plan fixtures/vm-plan/fail.json           # exit 1
driftarmor check --plan fixtures/nsg-plan/pass.json          # exit 0
driftarmor check --plan fixtures/frontdoor-plan/fail.json    # exit 1
driftarmor drift --plan fixtures/drift-plan/replace.json     # exit 1
pytest
```

## Providers

- `check` — Checkov policy packs (auto-detected from plan resources):
  - **AKS** — `azurerm_kubernetes_cluster` (+ node pools)
  - **Azure SQL** — `azurerm_mssql_server` / `_database` / `_firewall_rule`
  - **SQL Managed Instance** — `azurerm_mssql_managed_instance`
  - **Storage** — `azurerm_storage_account` (HTTPS, TLS, public blobs, network)
  - **Managed Redis** — `azurerm_managed_redis`
  - **Key Vault** — `azurerm_key_vault` (RBAC, purge protection, network)
  - **ACR** — `azurerm_container_registry` (local auth, anonymous pull, network)
  - **Service Bus** — `azurerm_servicebus_namespace` (auth, TLS, inline network rules)
  - **VM** — `azurerm_linux_virtual_machine` / `azurerm_windows_virtual_machine`
  - **NSG** — `azurerm_network_security_group` / `azurerm_network_security_rule`
  - **Front Door** — `azurerm_cdn_frontdoor_profile` / `_firewall_policy` / `_security_policy`
- `drift` — provider-agnostic plan-diff (any Terraform plan JSON); Service Bus
  queues, topics, subscriptions, and legacy standalone network rules are grouped
  with the Service Bus product even though they do not activate namespace checks

### AKS

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `aks.cluster.present` | fail | `azurerm_kubernetes_cluster` create/update in plan |
| `aks.node_pool.present` | fail | Default node pool **or** `azurerm_kubernetes_cluster_node_pool` |
| `aks.monitor.oms_or_dcr` | fail | OMS agent block **or** `azurerm_monitor_data_collection_rule` |
| `aks.monitor.prometheus_manual` | manual | Reminder to confirm Azure Monitor managed Prometheus |
| `aks.rbac.azure_rbac` | fail | Azure RBAC / Kubernetes RBAC enabled |
| `aks.network.private_or_authorized` | warn | Private cluster **or** authorized API IP ranges |

### Azure SQL

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `sql.public_network` | fail | `public_network_access_enabled` is false (server) |
| `sql.entra_admin` | fail | `azuread_administrator` block (server) |
| `sql.min_tls` | fail | `minimum_tls_version` 1.2+ (server) |
| `sql.firewall_any_ip` | fail | Firewall rule must not allow `0.0.0.0-255.255.255.255` |
| `sql.tde` | fail | `transparent_data_encryption_enabled` on database |

### SQL Managed Instance

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `sqlmi.public_data_endpoint` | fail | `public_data_endpoint_enabled` must not be true |
| `sqlmi.min_tls` | fail | `minimum_tls_version` 1.2+ |
| `sqlmi.entra_admin` | fail | `azuread_administrator` block |
| `sqlmi.identity` | warn | `identity` block (SystemAssigned / UserAssigned) |

### Storage

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `storage.https_only` | fail | HTTPS / secure transfer required |
| `storage.min_tls` | fail | `min_tls_version` TLS 1.2+ |
| `storage.blob_public_access` | fail | Public blob / nested public access disabled |
| `storage.network_restricted` | warn | Public network off **or** network rules `default_action = Deny` |

### Managed Redis

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `redis.public_network` | fail | `public_network_access` is `Disabled` |
| `redis.client_protocol` | fail | `default_database.client_protocol` is `Encrypted` (default) |
| `redis.access_keys_auth` | fail | `access_keys_authentication_enabled` must not be true |
| `redis.identity` | warn | `identity` block (SystemAssigned / UserAssigned) |

### Key Vault

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `keyvault.rbac_authorization` | fail | Azure RBAC authorization enabled |
| `keyvault.purge_protection` | fail | `purge_protection_enabled` is true |
| `keyvault.network_restricted` | warn | Public network off **or** network ACLs `default_action = Deny` |

### Azure Container Registry

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `acr.admin_disabled` | fail | Local admin account disabled |
| `acr.anonymous_pull_disabled` | fail | Anonymous image pulls disabled |
| `acr.network_restricted` | warn | Public network off **or** network rules `default_action = Deny` |

### Service Bus

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `servicebus.local_authentication` | fail | Local/SAS authentication disabled in favor of Microsoft Entra ID |
| `servicebus.min_tls` | fail | `minimum_tls_version` is 1.2 |
| `servicebus.network_restricted` | warn | Public network off **or** namespace network rules default to Deny |

### Virtual Machines

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `vm.encryption_at_host` | fail | `encryption_at_host_enabled` |
| `vm.trusted_launch` | fail | `secure_boot_enabled` **and** `vtpm_enabled` |
| `vm.linux_password_auth` | fail | Linux only: `disable_password_authentication` |
| `vm.managed_identity` | warn | `identity` block (SystemAssigned / UserAssigned) |

### Network Security Groups

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `nsg.open_ssh_internet` | fail | Inbound Allow SSH (22) from `*`, `Internet`, or `0.0.0.0/0` |
| `nsg.open_rdp_internet` | fail | Inbound Allow RDP (3389) from the Internet |
| `nsg.open_all_internet` | fail | Inbound Allow all ports (`*`) from the Internet |

### Front Door

| Rule id | Severity on fail | What it checks |
|---------|------------------|----------------|
| `frontdoor.waf_attached` | fail | Profile plan includes a WAF / security policy resource |
| `frontdoor.waf_enabled` | fail | Firewall policy `enabled` is not false |
| `frontdoor.waf_prevention` | fail | Firewall policy `mode` is `Prevention` |
| `frontdoor.waf_managed_rules` | fail | Firewall policy has a `managed_rule` block |

## Founder dogfood

Track misses while using this on real plans: [`wedge-miss-list.md`](wedge-miss-list.md).
