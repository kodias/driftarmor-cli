# Key Vault plan fixtures

| File | Expectation |
|------|-------------|
| `pass.json` | Azure RBAC and purge protection enabled, public network disabled -> exit `0` |
| `fail.json` | Access policies, no purge protection, and an unrestricted public network -> exit `1` (network rule is `warn`) |

```bash
driftarmor check --plan fixtures/keyvault-plan/pass.json --json
driftarmor check --plan fixtures/keyvault-plan/fail.json --json
```
