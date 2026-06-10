---
id: WAF-EVASION-18
title: HTTP Response Size Limit Abuse
category: Evasion Techniques
severity_range: Medium-Critical
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-18: HTTP Response Size Limit Abuse

## Summary

WAFs often have a maximum response body size they will inspect. Once this limit is exceeded, the remaining response content passes through without inspection. Attackers can pad responses to hide malicious content beyond the inspection boundary.

## When to Use

- Against cloud WAFs (e.g., Google Cloud Platform WAF - 8KB limit)
- When exploiting vulnerabilities that output large amounts of data
- For blind injection attacks where output appears later in the response

## Technique

1. Determine the WAF's inspection size limit
2. Pad the response with benign data to exceed the limit
3. Place the malicious payload after the limit boundary

## GCP WAF Example

Google Cloud Platform's WAF has a known ~8KB response inspection limit. Responses exceeding this size pass the excess content without inspection.

## Payload Example

```sql
-- SQL injection with padding before the actual payload
SELECT CONCAT(
  REPEAT('A', 8192),  -- Pad to exceed 8KB limit
  '<script>alert(1)</script>'  -- Actual payload (not inspected)
);
```

## References

- GCP WAF bypass writeups
