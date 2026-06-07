# WSTG Authorization (ATHZ)

5 tests for insecure direct object references, privilege escalation, authorization bypass, and OAuth weaknesses.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| ATHZ-01 | Testing for Insecure Direct Object References | Access other users data by changing ID parameter |
| ATHZ-02 | Testing for Bypassing Authorization Schema | Forced browsing, HTTP method override |
| ATHZ-03 | Testing for Privilege Escalation | Vertical/horizontal privilege escalation |
| ATHZ-04 | Testing for Insecure Direct Object References (API) | IDOR in REST/GraphQL endpoints |
| ATHZ-05 | Testing for OAuth and Authorization Weaknesses | CSRF in OAuth flow, redirect URI tampering |

## Workflow

1. `get_wstg_test("WSTG-ATHZ-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request` with modified IDs/roles
3. `track_test("WSTG-ATHZ-NN")` — record coverage
4. `log_finding()` — if authorization flaw found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- IDOR: get_technique_guide("AUTHZ") — parameter tampering, forced browsing
- Priv esc: get_technique_guide("AUTHZ") — role/header manipulation
- Direct access: get_technique_guide("AUTHZ") — forced browsing of admin endpoints

## Related PortSwigger Guides

- access-control.md
- oauth.md

## Burp Tools

- repeater.send, proxy.history, intruder (ID enumeration), target.scope

## Key Checks

- Numeric ID in URL/body — increment/decrement to access other accounts
- Admin functionality accessible via direct path (/admin)
- HTTP methods: POST to bypass GET restrictions
- OAuth redirect_uri accepts open redirect
- GraphQL aliases to query unauthorized data

## Reference
- Auth checklist: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/authentication-security-testing.md
- Race conditions: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/race-conditions.md
- Query API: ?ask=<question>
