# WSTG API Testing (APIT)

3 tests for GraphQL, REST, and SOAP web services.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| APIT-01 | Testing GraphQL | Introspection enabled, batching attacks, alias abuse |
| APIT-02 | Testing REST APIs | Rate limiting, auth bypass, mass assignment |
| APIT-03 | Testing SOAP/XML Web Services | XML external entities, schema manipulation |

## Workflow

1. `get_wstg_test("WSTG-APIT-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request`, `burp_scanner`
3. `track_test("WSTG-APIT-NN")` — record coverage
4. `log_finding()` — if API vuln found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- API auth bypass: get_technique_guide("AUTHN") — JWT manipulation, OAuth misconfig
- API injection: get_technique_guide("SQLI"/"XSS") — parameter-based payloads
- API SSRF: get_technique_guide("SSRF") — URL parameter manipulation
- API rate limiting: get_technique_guide("AUTHN") — rate limit bypass

## Related PortSwigger Guides

- graphql.md
- api-testing.md

## Burp Tools

- repeater.send, scanner, proxy.history, intruder

## Key Checks

- GraphQL introspection query returns full schema
- API returns detailed error messages with stack traces
- Missing rate limiting on auth/login endpoints
- Mass assignment: sending unexpected fields modifies them
- XML SOAP requests accept external entities
- CORS headers allow credentialled cross-origin requests
- API versioning allows accessing deprecated endpoints

## Reference
- API checklists: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/api-security-testing.md
- GraphQL: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/graphql-security-testing.md
- Query API for deeper detail: ?ask=<question>
