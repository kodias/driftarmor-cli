# Service Bus plan fixtures

| File | Expectation |
|------|-------------|
| `pass.json` | Local authentication disabled, minimum TLS 1.2, and inline network rules default to `Deny` -> exit `0` |
| `fail.json` | Local authentication enabled, minimum TLS 1.0, and public network access enabled -> exit `1` (network rule is `warn`) |

```bash
driftarmor check --plan fixtures/servicebus-plan/pass.json --json
driftarmor check --plan fixtures/servicebus-plan/fail.json --json
```
