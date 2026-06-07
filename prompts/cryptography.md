# WSTG Cryptography (CRYP)

4 tests for weak TLS configuration, padding oracle attacks, unencrypted sensitive data, and weak encryption algorithms.

## Test List

| ID | Test | Objective |
|----|------|-----------|
| CRYP-01 | Testing for Weak Transport Layer Security | Outdated TLS versions, weak cipher suites |
| CRYP-02 | Testing for Padding Oracle | CBC padding oracle allows data decryption |
| CRYP-03 | Testing for Sensitive Information Sent via Unencrypted Channels | PII, credentials, tokens over HTTP |
| CRYP-04 | Testing for Weak Encryption | Custom crypto, MD5/SHA1 hashing, weak key generation |

## Workflow

1. `get_wstg_test("WSTG-CRYP-NN")` — load methodology
2. Execute via Burp: `burp_repeater_send_request`, manual TLS version/cipher checks
3. `track_test("WSTG-CRYP-NN")` — record coverage
4. `log_finding()` — if crypto weakness found
5. **Immediately exploit:** queue vuln, get_technique_guide(), execute payloads via Burp, mark_exploited()

## Exploitation

- Weak TLS: downgrade to TLS 1.0, capture traffic for offline decryption
- Padding oracle: get_technique_guide("CRYP") — exploit CBC padding to decrypt/forge
- Predictable RNG: collect samples, predict session tokens
- Hash comparison timing: time-based user enumeration or token forgery

## Related PortSwigger Guides

- essential-skills.md

## Burp Tools

- repeater.send, proxy.history (mixed content detection)

## Key Checks

- TLS 1.0/1.1 still supported
- Weak ciphers: RC4, DES, 3DES
- Mixed content: HTTPS page loading HTTP resources
- Password hashes using MD5, SHA1, or unsalted formats
- Custom encryption in client-side JS
- Predictable IV or nonce

## Reference
- JWT: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/jwt-security-testing.md
- Insecure deserialization: https://manojxshrestha.gitbook.io/playbook/web-vulnerability-testing-checklist/insecure-deserialization.md
- Query API: ?ask=<question>
