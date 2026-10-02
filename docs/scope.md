# Authorized scope policy

1. Default deny until a target is explicitly listed.
2. Every network request must pass scope validation.
3. Every redirect destination must be validated again.
4. Hostnames must not bypass IP restrictions.
5. The system must not discover and test unrelated public targets.
6. Credentials and sessions belong only to their authorized project.
7. Potentially destructive actions require a separate policy and explicit approval.
8. The initial version excludes shell access, privilege escalation, lateral movement and persistence.

Current offline configuration example:

```json
{
  "allowed_schemes": ["http", "https"],
  "allowed_hosts": ["127.0.0.1", "localhost"],
  "allowed_ports": [8080, 5000],
  "allowed_paths": ["/"],
  "denied_paths": ["/admin/delete", "/api/destructive"]
}
```

`src/scope/scope-guard.ts` parses an absolute URL and checks its scheme, exact
host, effective port and normalized path. Empty allowlists deny access, and a
denied path takes precedence over an allowed path. Path rules match complete
path segments: `/api` includes `/api/users`, but not `/apiv2`.

To authorize a domain and all its subdomains without listing each host, use
`allowed_domains` (see `configs/scope.domain.example.json`). For example,
`["example.test"]` includes `example.test`, `oa.example.test`, and
`dev.oa.example.test`, but not `fake-example.test` or
`example.test.evil.test`. `allowed_hosts` remains exact-match only.
`denied_hosts` excludes an exact host and takes precedence over both allowlists;
it does not automatically exclude that host's subdomains. These two new fields
are optional, so older local configurations keep their meaning. Use a real,
explicitly authorized domain in local configuration; `example.test` is only a
non-network demonstration name. Do not use a public suffix (such as `co.uk`)
as a domain rule: this version does not check the public suffix list.

Path entries are prefixes with path-segment boundaries, so they do not need to
list every page. Use `/` to authorize the whole host, or use entries such as
`/api` and `/app` to authorize only those branches. Add narrower exceptions to
`denied_paths`; denied entries always take precedence.

Scope Guard itself remains offline. The restricted HTTP GET capability resolves
the host, permits only explicitly listed IP addresses, pins the selected address
for the connection, and passes every redirect destination through Scope Guard
again. A domain rule by itself does not authorize resolved IPs or update the
separate local authorization registry. The current crawler and several analysis
workflows also stay on the seed URL's exact origin, even when a broader domain
is configured; this change does not silently expand crawling to subdomains.
