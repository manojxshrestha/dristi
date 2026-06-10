---
name: waf-encoding-obfuscation
description: Skill for obfuscating payloads using various encoding techniques to bypass WAF signature detection. Covers URL encoding, Unicode, HTML entities, mixed encoding, alternative charsets, and the obfu.py tool. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 25
---

# WAF Encoding & Obfuscation

## Automated Scan (Run First)

```bash
# Use obfu.py to encode payloads in alternative charsets
python3 obfu.py -s '<svg/onload=prompt()//' -e ibm037 -ueo
```

## Crown Jewel Targets

- WAFs with charset normalization gaps
- Applications accepting alternative character encodings
- WAFs that don't inspect non-UTF-8 traffic
- Endpoints with multiple decoding layers

## Attack Surface Signals

- WAF blocks standard encoded payloads but allows specific encodings
- Backend accepts encodings that WAF does not normalize
- Different servers in chain normalize encoding differently

## Step-by-Step Methodology

1. Test single URL encoding: `%3Cscript%3E`
2. Test double URL encoding: `%253Cscript%253E`
3. Test Unicode normalization: `\u003cscript\u003e`
4. Test HTML entities: `&lt;script&gt;`
5. Test mixed encoding (tabs + encoding + newlines)
6. Test comment injection: `un/**/ion`
7. Test wildcard obfuscation: `/???/??t`
8. Test alternative charsets: IBM037, UTF-16, UTF-32
9. Test dynamic generation: `'al'+'er'+'t()'`
10. Test uninitialized variables: `$u/bin$u/cat$u`

## Encoding Reference

| Technique | Example | Effective Against |
|-----------|---------|-------------------|
| URL Encoding | `%3Cscript%3E` | Basic signature WAFs |
| Double Encoding | `%253Cscript%253E` | Single-decode WAFs |
| Unicode | `\u003cscript\u003e` | ASCII-only WAFs |
| HTML Entities | `&lt;script&gt;` | HTML context WAFs |
| Mixed Case | `<ScRipT>` | Case-sensitive rules |
| Comments | `un/**/ion` | Regex signature WAFs |
| Hex Encoding | `0x61646D696E` | String-based filters |
| Base64 | `YWRtaW4=` | String-based filters |
| Character Set | IBM037 | UTF-8 only WAFs |

## Alternative Charset Support

| Server Stack | Supported Encodings |
|-------------|-------------------|
| Nginx/Django-Python3 | IBM037, IBM500, cp875, IBM1026, IBM273 |
| Nginx/Django-Python2 | + UTF-16, UTF-32, UTF-32BE, IBM424 |
| Apache/Tomcat-JVM | ~28 charset encodings |
| IIS-ASP.NET | 35+ encodings including EBCDIC variants |

## Tool: obfu.py

```bash
# Encode payload to IBM037 with URL encoding output
python3 obfu.py -s 'param=<svg/onload=prompt()//' -e ibm037 -ueo

# Encode and URL-decode input first
python3 obfu.py -s '%3Cscript%3E' -e utf-16 -udi -ueo
```

## Common Root Causes

- WAFs normalize to UTF-8 by default; alternative encodings bypass detection
- Multiple decoding layers create confusion (WAF decodes once, backend decodes again)
- Charset negotiation differences between WAF and application server
- Different server stacks support different character encodings

## Gate 0 Validation

- [ ] Have I identified which encoding layers the WAF applies?
- [ ] Have I tried URL encoding?
- [ ] Have I tried double URL encoding?
- [ ] Have I tried alternative character sets?
- [ ] Have I documented which encoding worked?
