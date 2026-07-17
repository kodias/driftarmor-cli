# Azure Container Registry plan fixtures

| File | Expectation |
|------|-------------|
| `pass.json` | Admin and anonymous pull disabled, public network disabled -> exit `0` |
| `fail.json` | Admin and anonymous pull enabled, public network open with default action `Allow` -> exit `1` (network rule is `warn`) |

```bash
driftarmor check --plan fixtures/acr-plan/pass.json --json
driftarmor check --plan fixtures/acr-plan/fail.json --json
```
