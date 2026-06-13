# Awesome WAF - Training Data

Extracted from [0xInfection/Awesome-WAF](https://github.com/0xInfection/Awesome-WAF) and structured as training data compatible with the Dristi project format.

## Overview

This dataset contains comprehensive knowledge about Web Application Firewalls (WAFs) from an offensive security perspective. It is organized into:

- **waf-knowledge-base/** - Categorized WAF knowledge (like Dristi's knowledge/wstg/)
  - `01-detection-methodology/` - How to detect and fingerprint WAFs
  - `02-waf-fingerprints/` - Detection signatures for 110+ WAF vendors
  - `03-evasion-techniques/` - 21 categories of WAF evasion techniques
  - `04-known-bypasses/` - Documented payloads for bypassing 24+ WAF vendors
  - `05-tools-and-research/` - Tools, research papers, presentations, and scripts
- **skills/** (moved to `skills/waf-*/`) - Structured skill modules (like Dristi's skills/)
- **configs/** - Configuration templates

## Contents

| Category | Files | Description |
|----------|-------|-------------|
| Detection Methodology | 4 | Where to look, detection techniques, timing attacks, fingerprinting tools |
| WAF Fingerprints | 30+ | Per-vendor detection signatures with headers, cookies, response patterns |
| Evasion Techniques | 21 | Fuzzing, regex reversing, obfuscation, HPP, browser bugs, protocol abuse |
| Known Bypasses | 15+ | Documented payloads per WAF vendor |
| Tools & Research | 4+23 | Tool references, 12 papers, 11 presentations |
| Skills | 15 | Structured hunting/evasion skills in SKILL.md format |

## Credits

- Original project: [0xInfection/Awesome-WAF](https://github.com/0xInfection/Awesome-WAF)
- Initial compilation by Pinaki (0xInfection)
- Structured for training by the Dristi project
- License: Apache 2.0
