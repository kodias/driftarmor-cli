# Managed Redis plan fixtures

`pass.json` — public network Disabled, Encrypted protocol, access keys off, SystemAssigned identity.

`fail.json` — public Enabled, Plaintext protocol, access keys on, no identity.

```bash
driftarmor check --plan fixtures/redis-plan/pass.json --json
driftarmor check --plan fixtures/redis-plan/fail.json --json
```
