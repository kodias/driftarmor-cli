# Azure SQL plan fixtures

| File | Expectation |
|------|-------------|
| `pass.json` | Private network, Entra admin, TLS 1.2, narrow firewall, TDE on → exit `0` |
| `fail.json` | Public network, no Entra admin, TLS 1.0, any-IP firewall, TDE off → exit `1` |
