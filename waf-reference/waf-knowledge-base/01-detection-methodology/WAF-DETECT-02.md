---
id: WAF-DETECT-02
title: WAF Detection Techniques
category: Detection Methodology
severity_range: Informational-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-DETECT-02: WAF Detection Techniques

## Summary

11 proven techniques for detecting WAF presence and identifying the specific vendor.

## Test Objectives

- Confirm WAF presence through active probing
- Identify the specific WAF vendor for targeted evasion

## Test Steps

1. **Normal GET Request**: Send a baseline GET request to the target and observe response headers, cookies, and status codes
2. **cURL Testing**: Use cURL with verbose output to examine all response headers: `curl -s -v https://target.com/ 2>&1`
3. **Banner Grabbing**: Extract server banners and headers using `curl -s -I https://target.com/`
4. **Login Page Injection**: Send a request to the login page with a malicious payload to trigger WAF response
5. **Noisy XSS Payloads**: Send `<script>alert(1)</script>` to provoke WAF blocking behavior
6. **Path Traversal**: Send `../../../etc/passwd` to trigger path traversal rules
7. **SQL Sleep Injection**: Send `1' OR SLEEP(5)='1` to test for SQLi rules
8. **Outdated Protocols**: Request using HTTP/0.9 to see if WAF handles non-standard protocols differently
9. **Varying Server Headers**: Modify the Server header in requests to test WAF behavior
10. **FIN/RST Drop Testing**: Use HPing3 or Scapy to send FIN/RST packets and observe WAF connection handling
11. **Side-Channel Timing Attacks**: Measure response time variations to fingerprint WAF rules (see WAF-DETECT-03)

## Detection Criteria

Compare observed responses against known WAF fingerprints (see 02-waf-fingerprints/) to identify the vendor.
