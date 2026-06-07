# Security Policy

## Scope and authorized-use posture

Dristi is a methodology-and-tools framework for web application security testing. It contains WSTG-aligned test procedures, MCP server tooling, findings database infrastructure, and technique references derived from publicly disclosed bug-bounty reports and authorized engagements.

The framework is intended for use against assets you **own** or have **written authorization to assess**:

- Bug-bounty programs where the asset is explicitly in-scope (HackerOne, Bugcrowd, Intigriti, Immunefi, etc.)
- Authorized penetration-testing engagements with a signed Rules of Engagement
- Capture-the-flag (CTF) competitions
- Your own lab/infrastructure
- Security research on synthetic targets

The system includes structured validation workflows:

- Triage agents enforce a 7-Question Gate — scope, impact, and authorization checks
- Evidence-hygiene procedures cover cookie/PII redaction
- WSTG-aligned test tracking ensures methodology traceability

## What this framework explicitly excludes

Dristi does **not** include and is **not intended for**:

- Weaponizing 0-day exploits against unauthorized targets
- Post-exploitation tooling, persistence, or lateral-movement techniques
- Malware development, C2 frameworks, or stealth-evasion guidance
- Mass-targeting or unauthorized scanning at scale
- Supply-chain compromise
- Credential stuffing or ATO automation without authorization
- Any activity violating the CFAA, UK CMA, India IT Act, EU Cybercrime Directive, or equivalent local law

## Supported attack surface

By design, Dristi covers the **external web application attack surface**. It does not cover:

- Internal AD attacks (BloodHound, Kerberoasting, Pass-the-Hash, AD CS abuse)
- C2 tradecraft (Cobalt Strike, Sliver)
- Post-exploit persistence
- Evasion (AMSI bypass, EDR bypass)
- Internal L2 protocols (LLMNR, ARP spoofing)

## Reporting a security issue

If you discover a security issue in **this project itself**:

- **Methodology content** that could enable abuse: open a GitHub issue with the `security` label
- **Vulnerabilities in scripts**: same channel
- **Sensitive content accidentally shipped**: flag immediately

Do **not** post issues with unauthorized exploitation evidence.

## Disclosure of findings found using this framework

When Dristi helps you find a vulnerability in an authorized target:

1. **Validate first** — run triage/validate workflows
2. **Capture evidence with hygiene** — redact cookies, credentials, and PII
3. **Submit responsibly** — through the program's official channel
4. **Coordinate disclosure** — respect confidentiality terms
5. **Rotate test-account credentials** after submission

## Responsible-use commitments

By using Dristi, you acknowledge:

- You are responsible for ensuring authorization to test any target
- You will respect program scope, RoE, and the spirit of bug-bounty rules
- You will not use the framework to harm users (no real-PII exfiltration, no DoS)
- You will rotate credentials/tokens appearing in PoC artifacts after submission

## License and liability

Distributed under the Apache License 2.0, without warranty. The author(s) are not liable for misuse, unauthorized testing, or legal consequences of use.
