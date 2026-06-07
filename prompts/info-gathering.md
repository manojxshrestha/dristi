# WSTG Information Gathering (INFO)

10 tests for discovering attack surface, fingerprinting technologies, mapping entry points, and identifying information leaks.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| INFO-01 | Conduct Search Engine Discovery and Reconnaissance | Find exposed sensitive data via Google dorking, cached pages |
| INFO-02 | Fingerprint Web Server | Identify server software, version, OS via response headers |
| INFO-03 | Review Webserver Metafiles for Information Leakage | Check /robots.txt, /sitemap.xml, /security.txt for hidden paths |
| INFO-04 | Enumerate Applications on Webserver | Discover hidden apps, virtual hosts, non-standard ports |
| INFO-05 | Review Webpage Content for Information Leakage | Comments, hidden fields, JS source maps, data attributes |
| INFO-06 | Identify Application Entry Points | Map all URLs, forms, API endpoints, parameters |
| INFO-07 | Map Execution Paths Through Application | Trace user flows, state transitions, role-based paths |
| INFO-08 | Fingerprint Web Application Framework | Detect CMS, framework, version via cookies/headers/paths |
| INFO-09 | Fingerprint Web Application | Identify specific app, version, patch level |
| INFO-10 | Map Application Architecture | Load balancers, CDN, reverse proxies, auth providers |

## Workflow

For each test:

1. `get_wstg_test("WSTG-INFO-NN")` — load methodology + payloads
2. Execute via Burp: `burp_repeater_send_request`, `burp_proxy_history`, `burp_target_scope`
3. `track_test("WSTG-INFO-NN", "completed")` — record coverage
4. `log_finding()` — if vuln found, document with evidence

## Related PortSwigger Guides

- information-disclosure.md
- essential-skills.md

## Burp Tools

- repeater.send, proxy.history, target.scope, scanner

## Key Checks

- Internal IPs in headers (X-Forwarded-For, X-Real-IP)
- JS files for API keys, endpoints, source maps
- /.git/config, /.env, /backup/, /wp-content/ exposure
- Stack traces in error pages
- Third-party integrations in HTML comments

## Reference
- Full vulnerability checklists: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist
- Query API: ?ask=<question>
