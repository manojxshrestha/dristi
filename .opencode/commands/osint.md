---
name: osint
description: Passive intel — WHOIS, M365/Entra, cloud buckets, SPF/DMARC, subdomain takeover
---

# /osint

Gather passive intelligence on the target before any active scanning.

## What This Does

1. WHOIS and DNS footprinting
2. M365/Entra ID presence check
3. Cloud bucket enumeration (AWS S3, Azure Blob, GCP)
4. SPF/DMARC spoof check
5. Subdomain takeover fingerprinting

## Usage

```
/osint target.com
```

## When To Run

After `/scope`, before `/recon`. No active traffic touches the target.
