---
id: WAF-BYPASS-016
title: Cerber WordPress WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# Cerber WordPress WAF Bypass Payloads

## Username Enumeration

1. `/wp-json/wp/v2/users/` endpoint access
2. Author archive enumeration: `/?author=1`

## Admin Scripts Bypass

- Direct access to admin-ajax.php with crafted requests

## REST API Bypass

- WordPress REST API endpoints that bypass Cerber rules
