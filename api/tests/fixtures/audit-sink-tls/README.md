Test-only TLS material for `tests/audit_sink.rs`: a throwaway CA (`ca.pem`)
and a `localhost` certificate it signed (`server.pem`, key `server.key`),
valid for a century. Nothing outside the test suite trusts or uses them.
