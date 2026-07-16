# SQL Managed Instance plan fixtures

`pass.json` — public data endpoint off, TLS 1.2, Entra admin, SystemAssigned identity.

`fail.json` — public data endpoint on, TLS 1.0, no Entra admin / identity.

```bash
driftarmor check --plan fixtures/sqlmi-plan/pass.json --json
driftarmor check --plan fixtures/sqlmi-plan/fail.json --json
```
