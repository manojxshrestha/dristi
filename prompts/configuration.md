# WSTG Configuration and Deployment Management (CONF)

14 tests for misconfigurations in infrastructure, platform, HTTP headers, cloud storage, and security policies.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| CONF-01 | Test Network Infrastructure Configuration | Firewall rules, open ports, exposed admin interfaces |
| CONF-02 | Test Application Platform Configuration | Default credentials, unnecessary services, debug modes |
| CONF-03 | Test File Extensions Handling for Sensitive Info | Source code disclosure via .bak, .old, .sql extensions |
| CONF-04 | Review Old Backup and Unreferenced Files | Backup archives, temp files, CI artifacts |
| CONF-05 | Enumerate Infrastructure and Application Admin Interfaces | Admin panels, management consoles |
| CONF-06 | Test HTTP Methods | PUT, DELETE, TRACE, OPTIONS allowed |
| CONF-07 | Test HTTP Strict Transport Security | Missing HSTS header, short max-age |
| CONF-08 | Test RIA Cross Domain Policy | crossdomain.xml, clientaccesspolicy.xml |
| CONF-09 | Test File Permission | Directory listing, world-readable configs |
| CONF-10 | Test for Subdomain Takeover | Unclaimed DNS CNAME to expired services |
| CONF-11 | Test Cloud Storage | Public S3 buckets, Azure blobs, GCS |
| CONF-12 | Test for Content Security Policy | Missing CSP, unsafe-inline, wildcard directives |
| CONF-13 | Test Path Confusion | Path traversal via URL normalization bypass |
| CONF-14 | Test Other HTTP Security Header Misconfigurations | X-Frame-Options, X-Content-Type-Options, Permissions-Policy |

## Workflow

1. `get_wstg_test("WSTG-CONF-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request`, `burp_scanner`
3. `track_test("WSTG-CONF-NN")` — record coverage
4. `log_finding()` — if misconfiguration found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- Default creds: get_technique_guide("AUTHN") — brute force, credential stuffing
- Directory listing: navigate to exposed directories, download files
- Stack traces: extract framework version, plan for framework-specific attack
- HTTP methods: get_technique_guide("INPV") — verb tampering to bypass auth

## Related PortSwigger Guides

- information-disclosure.md
- host-header.md
- web-cache-poisoning.md

## Burp Tools

- repeater.send, scanner, target.scope, proxy.history

## Key Checks

- OPTIONS response showing allowed HTTP methods
- HSTS missing on login/API endpoints
- Subdomain CNAME pointing to unclaimed services
- CSP with unsafe-inline or wildcard sources

## Reference
- Host header attacks: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/http-host-header-attacks.md
- Web cache poisoning: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/web-cache-poisoning.md
- File upload: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/file-upload-vulnerabilities.md
- Query API: ?ask=<question>
            