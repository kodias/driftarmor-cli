# VM plan fixtures

`pass.json` — Linux VM with encryption at host, Trusted Launch, password auth disabled, SystemAssigned identity.

`fail.json` — Linux VM missing those controls (exit 1; `vm.managed_identity` is warn).

```bash
driftarmor check --plan fixtures/vm-plan/pass.json --json
driftarmor check --plan fixtures/vm-plan/fail.json --json
```
