# WSTG Input Validation (INPV)

20 tests for injection vulnerabilities: XSS, SQLi, SSTI, SSRF, XXE, command injection, and more.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| INPV-01 | Testing for Reflected Cross-Site Scripting | Non-persistent XSS via URL parameters |
| INPV-02 | Testing for Stored Cross-Site Scripting | Persistent XSS in comments, profiles, posts |
| INPV-03 | Testing for HTTP Verb Tampering | Unexpected methods bypass input validation |
| INPV-04 | Testing for HTTP Parameter Pollution | Duplicate params override server-side logic |
| INPV-05 | Testing for SQL Injection | Classic, blind, time-based, error-based SQLi |
| INPV-06 | Testing for LDAP Injection | LDAP query manipulation via user input |
| INPV-07 | Testing for ORM Injection | Hibernate/Doctrine query injection |
| INPV-08 | Testing for XML Injection | XML parsing manipulation |
| INPV-09 | Testing for SSI Injection | Server-Side Includes injection |
| INPV-10 | Testing for XPath Injection | XPath query manipulation |
| INPV-11 | Testing for Code Injection | eval(), exec(), system() via input |
| INPV-12 | Testing for Command Injection | OS command injection via shell metacharacters |
| INPV-13 | Testing for Format String Injection | %x, %n format specifier leaks |
| INPV-14 | Testing for Incubated Vulnerabilities | Stored payload triggers later |
| INPV-15 | Testing for HTTP Splitting/Smuggling | CRLF injection, request smuggling |
| INPV-16 | Testing for HTTP Incoming Requests | SSRF via URL parameter |
| INPV-17 | Testing for Host Header Injection | Cache poisoning, password reset poisoning |
| INPV-18 | Testing for Server-Side Template Injection | SSTI in Jinja2, Twig, Freemarker |
| INPV-19 | Testing for Server-Side Request Forgery | SSRF to internal services, cloud metadata |
| INPV-20 | Testing for XML External Entity Injection | XXE read files, SSRF, DoS |

## Workflow

1. `get_wstg_test("WSTG-INPV-NN")` — load methodology + payloads
2. Execute via Burp: `burp_repeater_send_request`, `burp_scanner`, `burp_intruder`
3. `track_test("WSTG-INPV-NN")` — record coverage
4. `log_finding()` — if injection found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- XSS: get_technique_guide("XSS") — sink html_body, html_attribute, javascript_string, javascript_template
- SQLi: get_technique_guide("SQLI") — sink sql_string, sql_numeric — data extraction
- CMDi: get_technique_guide("CMDI") — sink command_shell — RCE
- SSTI: get_technique_guide("SSTI") — sink ssti_template — RCE or file read
- SSRF: get_technique_guide("SSRF") — sink ssrf_url — internal scan, cloud metadata
- Path traversal: sink path_traversal — file read
- XXE: get_technique_guide("XXE") — file read, SSRF, DoS

## Related PortSwigger Guides

- sql-injection.md, cross-site-scripting.md, ssrf.md, xxe.md
- ssti.md, os-command-injection.md, nosql-injection.md
- http-request-smuggling.md, host-header.md, prototype-pollution.md

## Burp Tools

- repeater.send, scanner, intruder, proxy.history

## Key Checks

- Parameter reflection in response (XSS)
- Error messages revealing SQL/XML structure
- Time-based delays for blind injection
- Out-of-band interaction (Burp Collaborator)
- WAF bypass via encoding, case mutation, parameter pollution

## Reference
- SQLi: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/sql-injection-sqli.md
- XSS: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/xss-cross-site-scripting.md
- SSRF: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/ssrf-server-side-request-forgery.md
- SSTI: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/ssti-server-side-template-injection.md
- Path traversal: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/path-traversal-directory-traversal-lfi.md
- XXE: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/xxe-xml-external-entity-injection.md
- OS command injection: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/os-command-injection.md
- NoSQL injection: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/nosql-injection.md
- Open redirect: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/open-redirect.md
- HTTP request smuggling: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/http-request-smuggling-desync-attacks.md
- Prototype pollution: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/prototype-pollution.md
- Insecure deserialization: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/insecure-deserialization.md
- API testing: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/api-security-testing.md
- Query API: ?ask=<question>
