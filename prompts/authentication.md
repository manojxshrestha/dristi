# WSTG Authentication (ATHN)

11 tests for credential transport, default credentials, lockout mechanisms, password policies, MFA, and session weaknesses.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| ATHN-01 | Testing for Credentials Transported over an Encrypted Channel | Passwords sent over HTTP, mixed content forms |
| ATHN-02 | Testing for Default Credentials | admin/admin, root/root, vendor defaults |
| ATHN-03 | Testing for Weak Lock Out Mechanism | No rate limiting, lockout bypass via IP rotation |
| ATHN-04 | Testing for Bypassing Authentication Schema | Direct page access, parameter tampering, SQLi in login |
| ATHN-05 | Testing for Vulnerable Remember Password | Credentials stored in plaintext cookies |
| ATHN-06 | Testing for Browser Cache Weaknesses | Sensitive pages cached after logout |
| ATHN-07 | Testing for Weak Password Policy | No complexity requirements, short minimum length |
| ATHN-08 | Testing for Weak Security Question/Answer | Guessable answers, no rate limiting on security questions |
| ATHN-09 | Testing for Weak Password Change or Reset Functionality | Token in URL, no old password required, predictable reset tokens |
| ATHN-10 | Testing for Weaker Authentication in Alternative Channel | Mobile API has weaker auth than web |
| ATHN-11 | Testing Multi-Factor Authentication | MFA bypass, SMS interception, TOTP reuse |

## Workflow

1. `get_wstg_test("WSTG-ATHN-NN")` — load methodology + payloads
2. Execute via Burp: `burp_repeater_send_request`, `burp_intruder` for brute force
3. `track_test("WSTG-ATHN-NN")` — record coverage
4. `log_finding()` — if auth bypass or credential weakness found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- Weak password policy: get_technique_guide("AUTHN") — brute force, credential stuffing
- MFA bypass: get_technique_guide("AUTHN") — step omission, token reuse, SMS interception
- JWT issues: get_technique_guide("JWT") — alg:none, weak secret, kid injection
- OAuth misconfig: get_technique_guide("OAUTH") — CSRF, redirect_uri bypass
- Password reset: get_technique_guide("AUTHN") — token prediction, host header injection

## Related PortSwigger Guides

- authentication.md
- jwt.md
- oauth.md

## Burp Tools

- repeater.send, intruder, scanner, proxy.history

## Key Checks

- Login page accessible over HTTP
- Password reset token in URL or email
- MFA can be skipped by omitting step parameter
- Lockout counter resets on password change
- JWT with alg:none or weak secret

## Reference
- Auth checklist: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/authentication-security-testing.md
- JWT: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/jwt-security-testing.md
- OAuth: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/oauth-authentication.md
- Query API: ?ask=<question>
