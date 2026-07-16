# Front Door plan fixtures

`pass.json` — profile + WAF (enabled, Prevention, managed rules) + security policy.

`fail.json` — profile + WAF disabled / Detection / no managed rules (still attached via firewall policy).

```bash
driftarmor check --plan fixtures/frontdoor-plan/pass.json --json
driftarmor check --plan fixtures/frontdoor-plan/fail.json --json
```
