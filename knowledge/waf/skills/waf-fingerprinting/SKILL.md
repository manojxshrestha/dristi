---
name: waf-fingerprinting
description: Skill for identifying Web Application Firewall vendors through HTTP response analysis, cookie inspection, header examination, and side-channel techniques. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 110
---

# WAF Fingerprinting Skill

## Automated Scan (Run First)

```bash
# WAFW00F - Industry standard fingerprinting
wafw00f https://target.com

# IdentYwaf - Blind WAF detection
identYwaf https://target.com

# Manual header inspection
curl -s -v https://target.com/ 2>&1 | grep -i "server\|x-\|set-cookie"
```

## Crown Jewel Targets

- **Login pages** - Often have different WAF rules than public pages
- **API endpoints** - May have weaker protection than web pages
- **File upload endpoints** - Often less inspected
- **Admin panels** - May have whitelist bypasses

## Attack Surface Signals

| Signal | What It Indicates |
|--------|-------------------|
| `cf-ray` header | Cloudflare |
| `X-AMZ-ID` header | AWS WAF |
| `X-Iinfo` header | Imperva Incapsula |
| `BigIP` cookie | F5 BIG-IP ASM |
| `visid_incap` cookie | Imperva Incapsula |
| `Server: cloudflare` | Cloudflare |
| `X-Scanner` header | ModSecurity CRS |
| Response code 999 | WebKnight |
| Response code 493 | 360 WAF |

## Step-by-Step Methodology

1. Send baseline GET request and record all response headers
2. Look for WAF-specific cookies in `Set-Cookie` headers
3. Examine `Server` header for WAF identification strings
4. Send a malicious payload (e.g., `<script>alert(1)</script>`) and observe block page
5. Analyze block page content for vendor-specific branding
6. Check response codes for non-standard values (999, 493, 406, etc.)
7. Use WAFW00F for automated fingerprinting
8. Verify fingerprint with IdentYwaf for blind detection
9. Document all identified headers, cookies, and response patterns
10. Cross-reference against known WAF fingerprints database

## Payload & Detection Patterns

```bash
# Payload to trigger WAF response
curl -s -k "https://target.com/?q=<script>alert(1)</script>"

# Timing-based fingerprinting
time curl -s -k "https://target.com/?q=1' OR SLEEP(5)='1"
```

## Common Root Causes

- WAFs leave identifiable artifacts in HTTP responses
- Default configurations expose vendor information
- Block pages contain branding that reveals the WAF vendor
- Cookie naming conventions are vendor-specific
- Header manipulation patterns (jumbling, ordering) are unique per vendor

## Bypass Techniques

- Once fingerprinted, use vendor-specific bypasses (see evasion-techniques and known-bypasses)
- WAFs with known fingerprints have documented bypass payloads

## Gate 0 Validation

- [ ] Have I identified the specific WAF vendor?
- [ ] Have I confirmed the WAF detection with at least 2 independent indicators?
- [ ] Have I documented all identification artifacts (headers, cookies, response codes)?
