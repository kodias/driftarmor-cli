# NSG plan fixtures

`pass.json` — NSG allows SSH only from `10.0.0.0/8`.

`fail.json` — NSG allows SSH/RDP/all ports from the Internet (`*`, `Internet`, `0.0.0.0/0`).

```bash
driftarmor check --plan fixtures/nsg-plan/pass.json --json
driftarmor check --plan fixtures/nsg-plan/fail.json --json
```
