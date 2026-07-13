# Storage plan fixtures

| File | Expectation |
|------|-------------|
| `pass.json` | HTTPS, TLS1_2, no public blobs, public network disabled → exit `0` |
| `fail.json` | Opposite settings → exit `1` (network rule is `warn`) |
