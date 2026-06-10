---
id: WAF-EVASION-01
title: Fuzzing / Bruteforcing
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-01: Fuzzing / Bruteforcing

## Summary

Fuzzing is a brute-force approach to WAF evasion that involves systematically sending large volumes of varied payloads to discover which patterns pass through the WAF. By iterating through wordlists of known bypasses, obfuscation patterns, and edge cases, an attacker can identify filter gaps and blind spots in the WAF's rule set.

## When to Use

- When the WAF is known to block a specific attack vector but the exact filter rules are unknown
- During black-box testing where no source code or WAF configuration is available
- To rapidly enumerate which characters, keywords, and encoding schemes are permitted
- Against WAFs that have rate-limiting but not IP-based blocking (low-and-slow fuzzing)

## Technique Details

Fuzzing relies on sending a high volume of requests with mutated payloads derived from comprehensive wordlists. The response (status code, response body, response time, block page) indicates whether the payload was detected or allowed through. Common fuzzing strategies include:

- **Character-level fuzzing**: Injecting individual special characters to determine filter boundaries.
- **Keyword mutation**: Iterating through case variations, encoding schemes, and comment insertions for blocked keywords.
- **Blind fuzzing**: Sending time-based payloads (e.g., SQL time delays) and measuring response latency to infer filter behavior.
- **User-Agent rotation**: Cycling through randomized User-Agent strings to avoid signature-based bot detection.
- **Latency profiling**: When blocked, introducing incremental delays between retries to avoid triggering rate-limit thresholds.

## Payload Examples

```bash
# Fuzzing with ffuf using SecLists
ffuf -u https://target.com/search.php?q=FUZZ \
  -w /usr/share/seclists/Fuzzing/special-chars.txt \
  -w /usr/share/seclists/Fuzzing/XSS-Fuzzing.txt \
  -mr "blocked|denied|suspicious" \
  -fc 403,406

# Blind time-based SQLi fuzzing
ffuf -u https://target.com/page?id=FUZZ \
  -w fuzz-db/attack/sqli/time-based.txt \
  -t 5 -p 0.5-2.0 \
  -ac

# Rate-limit bypass with randomized delays
for payload in $(cat payloads.txt); do
  sleep $((RANDOM % 3 + 1))
  curl -s -o /dev/null -w "%{http_code}" \
    -A "Mozilla/$(shuf -i 5-95 -n 1).0" \
    "https://target.com/?q=$payload"
done
```

```bash
# proxychains rotation for IP diversity
proxychains4 -q ffuf -u https://target.com/login -X POST \
  -d "user=admin&pass=FUZZ" \
  -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
  -t 1
```

## Detection & Bypass Notes

**Detection:**
- WAFs can detect fuzzing by monitoring request rate, User-Agent entropy, and unusual character distributions.
- Rate-limiting and CAPTCHA challenges are common counter-measures.
- IP reputation databases flag sources that produce high volumes of anomalous requests.

**Bypass:**
- Distribute fuzzing across multiple IPs (proxychains, rotating proxies, TOR).
- Use low-and-slow approaches with random inter-request delays.
- Split fuzzing across long time windows to appear as organic traffic.
- Combine fuzzing with legitimate browsing patterns interleaved between test requests.

**Drawback:** IPs involved in fuzzing are frequently blocked by WAFs and CDN edge firewalls, reducing the usable lifetime of each source IP.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://github.com/danielmiessler/SecLists
- https://github.com/fuzzdb-project/fuzzdb
- https://github.com/ffuf/ffuf
