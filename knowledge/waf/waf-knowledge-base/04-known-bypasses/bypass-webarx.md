---
id: WAF-BYPASS-013
title: WebARX WAF Bypass Payloads
category: Known Bypasses
severity_range: Medium-Critical
---

# WebARX WAF Bypass Payloads

## XSS Bypasses

- All protections bypassed via specific whitelist string

## LFI Bypasses

- All protections bypassed via specific whitelist string

## SQLi Bypasses

- All protections bypassed via specific whitelist string

## Technique Notes

- WebARX (WordPress plugin) has a critical weakness: a whitelist string that bypasses ALL protections
- Finding the whitelist string requires reverse-engineering the plugin source
