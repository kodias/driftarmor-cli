# AKS plan fixtures

Hand-authored subsets of `terraform show -json <planfile>` for DriftArmor acceptance tests.

## Shape

Minimum fields DriftArmor / Checkov need:

- `format_version` — Terraform plan JSON version string
- `planned_values.root_module.resources[]` — Checkov terraform_plan framework reads this
- `resource_changes[]` — DriftArmor AKS detection + CLI OR logic (`oms`/`DCR`, node pools):
  - `address`, `mode`, `type`, `name`
  - `change.actions` — e.g. `["create"]` or `["update"]`
  - `change.after` — planned attribute object (or `null` on destroy)
  - `change.after_unknown` — map of attributes unknown until apply
- `configuration` — optional but present in real `terraform show -json` output

## `after_unknown`

Terraform marks values computed at apply time under `after_unknown`. DriftArmor / Checkov treat unknown attributes as **absent** for pass/fail (same as null). Example in `pass.json`: `fqdn` is unknown while `oms_agent` is known in `after`.

## Files

| File | Intent |
|------|--------|
| `pass.json` | AKS cluster with OMS, RBAC, private cluster, default node pool → exit `0` |
| `fail.json` | AKS cluster missing OMS/DCR (and RBAC) → exit `1`, includes `aks.monitor.oms_or_dcr` fail |
| `no_aks.json` | Non-pack resources only → exit `0`, "nothing to check" |

## Regenerate from a real plan (optional)

```bash
terraform plan -out=tfplan
terraform show -json tfplan > fixtures/aks-plan/mine.json
```
