# WSTG Identity Management (IDNT)

5 tests for role definitions, user registration, account provisioning, enumeration, and username policies.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| IDNT-01 | Test Role Definitions | Unclear role boundaries, overlapping privileges |
| IDNT-02 | Test User Registration Process | Self-registration allows privileged roles, no email verification |
| IDNT-03 | Test Account Provisioning Process | Auto-provisioned accounts, default passwords |
| IDNT-04 | Testing for Account Enumeration and Guessability | Error messages reveal existing usernames/emails |
| IDNT-05 | Testing for Weak or Unenforced Username Policy | Predictable usernames (user001, admin), no uniqueness check |

## Workflow

1. `get_wstg_test("WSTG-IDNT-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request` for registration/enumeration probes
3. `track_test("WSTG-IDNT-NN")` — record coverage
4. `log_finding()` — if identity management flaw found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- User enumeration: get_technique_guide("AUTHN") — enumerate valid usernames for brute force
- Weak registration: create accounts with spoofed attributes, mass registration
- Identity confusion: test role/attribute manipulation on signup

## Related PortSwigger Guides

- authentication.md
- essential-skills.md

## Burp Tools

- repeater.send, proxy.history, intruder (for username brute force)

## Key Checks

- Different error messages for existing vs non-existing usernames
- Registration allows setting role/privilege level
- Forgot password reveals if account exists
- Timed responses differ between valid/invalid usernames

## Reference
- Auth checklist: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/authentication-security-testing.md
- Query API: ?ask=<question>
