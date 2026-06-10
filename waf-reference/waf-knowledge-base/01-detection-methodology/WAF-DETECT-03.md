---
id: WAF-DETECT-03
title: Side-Channel Timing Attacks for WAF Fingerprinting
category: Detection Methodology
severity_range: Low-Medium
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-DETECT-03: Side-Channel Timing Attacks for WAF Fingerprinting

## Summary

Timing side-channel attacks can reveal which WAF rules are active by measuring response time differences between blocked and allowed requests. This technique was presented at USENIX WOOT'12.

## Test Objectives

- Map WAF rule sets through timing analysis
- Identify specific blocked patterns without triggering blocks
- Determine WAF rule granularity

## Methodology

1. Send baseline requests and measure average response time
2. Send payloads that progressively match known attack patterns
3. Measure response time differences:
   - Fast rejection (~ms) = early rule match (often blacklist-based)
   - Delayed rejection = deeper rule processing
   - No rejection = rule likely absent
4. Catalog timing signatures per payload class to build a rule presence map

## Key Insight

WAFs that return block responses faster for certain payload categories reveal which detection rules are positioned earlier in their rule chain. This allows attackers to identify which attack vectors are monitored and which may have weaker coverage.

## Remediation

WAF operators should randomize response timing and avoid distinguishable delay patterns.
