---
description: Pipeline Phase 1.75 — Passive OSINT: WHOIS, M365/Azure, third-party misconfigs, spoof check, cloud bucket enumeration
---

# OSINT (Passive)

Run passive OSINT to build target intelligence before active recon. This phase runs after AUTH and before RECON — the output feeds target context to all later phases.

## Input

Target domain(s) from Phase 1 (SCOPE) and any credentials/tokens from Phase 1.5 (AUTH).

## OSINT Workflow

### Step 1: Run OSINT script

```bash
bash scripts/tools/osint.sh <domain>
```

This runs 4 modules (no API keys needed):

| Module | Tool | Output | What it finds |
|--------|------|--------|---------------|
| domain_info | whois + msftrecon + Scopify | `osint/domain_info_general.txt`, `azure_tenant_domains.txt`, `scopify.txt` | WHOIS registrant, M365/Azure tenant, scope analysis |
| third_party_misconfigs | misconfig-mapper | `osint/3rdparts_misconfigurations.txt` | Exposed SaaS (Slack, Jira, GitHub, Confluence, etc.) |
| spoof | Spoofy | `osint/spoof.txt` | SPF/DMARC/DKIM spoofability |
| cloud_enum_scan | cloud_enum | `osint/cloud_enum.txt` | AWS S3, Azure Blob, GCP, DO Spaces buckets |

Skipped: `ip_info` (requires WHOISXML_API key).

Missing tools are gracefully skipped with a `[MISSING TOOLS]` warning — OSINT is informative, not blocking.

### Step 2: Parse results

Read each output file and extract actionable intel:

- **WHOIS**: Registrant organization, name servers, creation/expiry dates
- **Azure/M365**: Verified tenant ID, authentication endpoints
- **Scopify**: Potential scope-expansion domains
- **Third-party misconfigs**: Exposed internal tools, dev/staging environments
- **Spoof**: SPF hard/soft fail, DMARC policy (p=reject/quarantine/none), DKIM signing status
- **Cloud enum**: Open storage buckets, bucket names for further testing

### Step 3: Save OSINT deliverable

```
wstg_save_deliverable(
  deliverable_type='osint_analysis',
  content=<json or markdown summary of all findings>,
  producer_agent='osint'
)
```

### Step 4: Track

```
wstg_track_tool(tool_name='osint', status='run', notes='WHOIS + misconfig-mapper + Spoofy + cloud_enum')
```

## Output

- Files in `engagements/<eid>/recon/<domain>/osint/`
- `osint_analysis` deliverable consumed by Phase 4 (HUNT) agents for target intelligence

## Notes

- If `whois` is unavailable, domain_info is skipped (system package: `apt install whois`)
- The reconftw repo tools (msftrecon, Scopify, Spoofy, cloud_enum) are optional — install via `~/reconftw/install.sh`
- OSINT results are informational context, not blocking — proceed to Phase 2 (RECON) regardless
