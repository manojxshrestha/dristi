---
id: WAF-BYPASS-INDEX
title: Known WAF Bypasses Reference Index
category: Known Bypasses
severity_range: Medium-Critical
---

# Known WAF Bypasses Reference Index

This directory contains documented payloads and techniques for bypassing specific WAF vendors. Each file catalogs real-world bypass payloads organized by vulnerability class.

## Index

| # | Vendor | File | Bypass Types |
|---|--------|------|-------------|
| 1 | 360 (Qihoo) | bypass-360.md | XSS, SQLi |
| 2 | Airlock Ergon | bypass-airlock.md | SQLi (UTF-8 overlong) |
| 3 | AWS WAF | bypass-aws-waf.md | SQLi, XSS |
| 4 | Barracuda | bypass-barracuda.md | XSS (4), HTML Injection, RCE |
| 5 | Cerber (WordPress) | bypass-cerber.md | User Enum, Admin Bypass, REST API |
| 6 | Citrix NetScaler | bypass-netscaler.md | SQLi (HPP), XSS |
| 7 | Cloudbric | bypass-cloudbric.md | XSS |
| 8 | Cloudflare | bypass-cloudflare.md | XSS (11+), RCE |
| 9 | Comodo cWatch | bypass-comodo.md | XSS, SQLi |
| 10 | DotDefender | bypass-dotdefender.md | Firewall Disable, RCE, XSS (4+) |
| 11 | F5 BIG-IP | bypass-f5.md | XSS (4+), XXE, Dir Traversal |
| 12 | F5 FirePass | bypass-f5-firepass.md | SQLi |
| 13 | Fortinet FortiWeb | bypass-fortinet.md | XSS (2), CSP Bypass |
| 14 | Generic Bypasses | bypass-generic.md | Apache lowercase, IIS tabs |
| 15 | Imperva Incapsula | bypass-imperva.md | XSS (10+), SQLi, PrivEsc |
| 16 | Kona SiteDefender (Akamai) | bypass-kona-sitedefender.md | XSS (6+), HTML Injection |
| 17 | ModSecurity | bypass-modsecurity.md | XSS, RCE, SQLi (7+) |
| 18 | Profense | bypass-profense.md | CSRF, XSS (2) |
| 19 | StackPath | bypass-stackpath.md | XSS |
| 20 | Sucuri | bypass-sucuri.md | XSS (4), RCE/Smuggling |
| 21 | UrlScan | bypass-urlscan.md | Directory Traversal |
| 22 | WebARX | bypass-webarx.md | XSS, LFI, SQLi |
| 23 | WebKnight | bypass-webknight.md | XSS (4), SQLi |
| 24 | Wordfence | bypass-wordfence.md | XSS (4+), HTML Injection |
