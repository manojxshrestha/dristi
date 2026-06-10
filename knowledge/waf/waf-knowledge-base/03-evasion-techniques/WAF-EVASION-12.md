---
id: WAF-EVASION-12
title: Alternative Character Encodings
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-12: Alternative Character Encodings

## Summary

Alternative character encoding evasion exploits the difference between the WAF's character encoding assumptions and the server's actual encoding configuration. By encoding payloads using non-ASCII character sets (EBCDIC, UTF-16, UTF-32, IBM code pages), attackers can bypass WAF filters that only decode standard UTF-8 or Latin-1 input, while the backend application server decodes and processes the request correctly.

## When to Use

- Against WAFs deployed in front of application servers with non-default character encoding
- When the target platform supports multiple character encodings (Java/JSP, ASP.NET, Python)
- Against WAFs that only decode the most common encoding (UTF-8) but ignore or mishandle others
- When the WAF normalizes input to UTF-8 but the backend uses a different encoding internally

## Technique Details

Different application server platforms support different character encodings. By encoding the same characters in alternative code pages, the payload appears as benign bytes to a UTF-8-decoding WAF but is interpreted as valid attack syntax by the backend.

**Character encoding support per platform:**

| Platform | Supported Encodings |
|----------|-------------------|
| Nginx/uWSGI-Django-Python3 | IBM037, IBM500, cp875, IBM1026, IBM273 |
| Nginx/uWSGI-Django-Python2 | utf-16, utf-32, utf-32BE, IBM424 |
| Apache-TOMCAT8-JVM1.8-JSP | Big5, Big5-HKSCS, EUC-JP, EUC-KR, GB18030, GB2312, GBK, IBM-Thai, IBM00858, IBM01140, IBM01141, IBM01142, IBM01143, IBM01144, IBM01145, IBM01146, IBM01147, IBM01148, IBM01149, IBM037, IBM1026, IBM1047, IBM273, IBM277, IBM278, IBM280, IBM284, IBM285, IBM290, IBM297, IBM420, IBM424, IBM437, IBM500, IBM775, IBM850, IBM852, IBM855, IBM857, IBM860, IBM861, IBM862, IBM863, IBM864, IBM865, IBM866, IBM868, IBM869, IBM870, IBM871, IBM918, ISO-2022-CN, ISO-2022-JP, ISO-2022-KR, ISO-8859-1, ISO-8859-13, ISO-8859-15, ISO-8859-2, ISO-8859-3, ISO-8859-4, ISO-8859-5, ISO-8859-6, ISO-8859-7, ISO-8859-8, ISO-8859-9, JIS_X0201, JIS_X0212-1990, KOI8-R, KOI8-U, Shift_JIS, TIS-620, US-ASCII, UTF-16, UTF-16BE, UTF-16LE, UTF-32, UTF-32BE, UTF-32LE, UTF-8, windows-1250, windows-1251, windows-1252, windows-1253, windows-1254, windows-1255, windows-1256, windows-1257, windows-1258, x-Big5-Solaris, x-euc-jp-linux, x-EUC-TW, x-eucJP-Open, x-IBM10079, x-IBM1006, x-IBM1025, x-IBM1046, x-IBM1097, x-IBM1098, x-IBM1112, x-IBM1122, x-IBM1123, x-IBM1124, x-IBM1166, x-IBM1364, x-IBM1381, x-IBM1383, x-IBM300, x-IBM33722, x-IBM737, x-IBM833, x-IBM834, x-IBM856, x-IBM874, x-IBM875, x-IBM921, x-IBM922, x-IBM930, x-IBM933, x-IBM935, x-IBM937, x-IBM939, x-IBM942, x-IBM942C, x-IBM943, x-IBM943C, x-IBM948, x-IBM949, x-IBM949C, x-IBM950, x-IBM964, x-IBM970, x-ISCII91, x-ISO-2022-CN-CNS, x-ISO-2022-CN-GB, x-JIS0208, x-JISAutoDetect, x-Johab, x-MacArabic, x-MacCentralEurope, x-MacCroatian, x-MacCyrillic, x-MacDingbat, x-MacGreek, x-MacHebrew, x-MacIceland, x-MacRoman, x-MacRomania, x-MacSymbol, x-MacThai, x-MacTurkish, x-MacUkraine, x-PCK, x-SJIS_0213, x-UTF-16LE-BOM, x-UTF-32BE-BOM, x-UTF-32LE-BOM, x-windows-50220, x-windows-50221, x-windows-874, x-windows-949, x-windows-950, x-windows-iso2022jp |
| Apache-TOMCAT7-JVM1.6-JSP | ~28 encodings (similar subset to TOMCAT8) |
| IIS6/7.5/8/10-ASPX v4.x | 35+ encodings including: utf-8, utf-7, utf-16, utf-16BE, utf-32, utf-32BE, iso-8859-1 through iso-8859-16, windows-1250 through windows-1258, ibm037, ibm500, ibm850, ibm852, ibm855, ibm857, ibm860, ibm861, ibm862, ibm863, ibm864, ibm865, ibm866, ibm869, ibm870, ibm1026, ibm1047, ibm273, ibm277, ibm278, ibm280, ibm284, ibm285, ibm290, ibm297, ibm420, ibm424, ibm437, ibm775, big5, euc-jp, euc-kr, gb2312, gbk, shift_jis, us-ascii |

## Payload Examples

```python
# Python script (obfu.py style) for generating alternative encoding payloads
def encode_payload(payload, encoding='utf-16'):
    try:
        return payload.encode(encoding)
    except:
        return None

# UTF-16 encoded XSS payload
# Original: <script>alert(1)</script>
# UTF-16LE: \xff\xfe<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00...
```

```http
# HTTP request with UTF-16 encoded payload
POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded; charset=utf-16

q=%FF%FE%3C%00s%00c%00r%00i%00p%00t%00%3E%00a%00l%00e%00r%00t%00(%001%00)%00<%00/%00s%00c%00r%00i%00p%00t%00%3E%00
```

```http
# Using IBM037 (EBCDIC) encoding
POST /submit HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded; charset=ibm037

q=%7C%81%93%85%99%A3%60%81%(1)`
# EBCDIC encoding of 'alert(1)' 
```

```python
# Reference obfu.py-style generation
"""
obfu.py - Alternative character encoding generator

Usage:
  python obfu.py --payload "<script>alert(1)</script>" --encoding utf-16
  python obfu.py --payload "1 union select 1,2,3" --encoding ibm037
"""
```

## Detection & Bypass Notes

**Detection:**
- WAFs that convert all input to a standard encoding (UTF-8) before inspection are resistant.
- Modern WAFs that specify `charset=utf-8` in Content-Type and reject multi-encoding requests prevent this.
- WAFs that validate Content-Type charset declarations against actual byte patterns can detect mismatches.

**Bypass:**
- The Content-Type header's `charset` parameter must match the actual encoding of the POST body.
- For GET requests, URL encoding must match the declared or implied encoding.
- Test each platform's supported encodings individually to find the one that bypasses the WAF.
- Combine with other encoding layers: first encode characters in an alternative charset, then URL-encode the resulting raw bytes.
- UTF-7 is particularly effective against WAFs that don't decode it — e.g., `+ADw-script+AD4-alert(1)+ADw-/script+AD4-`.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://tools.ietf.org/html/rfc1345
- https://www.unicode.org/charts/
- https://github.com/0xInfection/obfu.py
