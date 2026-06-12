---
description: Pipeline Phase 3 — Passive Intel: WHOIS, M365/Azure, third-party misconfigs, spoof check, cloud bucket enumeration
mode: subagent
permission:
  read: allow
  bash: allow
  edit: deny
  grep: allow
  glob: allow
---

# Intel (Passive)

Run passive intel to build target intelligence before active recon. This phase runs after AUTH and before RECON — the output feeds target context to all later phases.

## Input

Target domain(s) from Phase 1 (SCOPE) and any credentials/tokens from Phase 2 (AUTH).

## Intel Workflow

### Step 1: Run Intel script

```bash
bash scripts/tools/phase-intel.sh <domain>
```

This runs 4 modules (no API keys needed):

| Module | Tool | Output | What it finds |
|--------|------|--------|---------------|
| domain_info | whois + msftrecon + Scopify | `intel/domain_info_general.txt`, `azure_tenant_domains.txt`, `scopify.txt` | WHOIS registrant, M365/Azure tenant, scope analysis |
| third_party_misconfigs | misconfig-mapper | `intel/3rdparts_misconfigurations.txt` | Exposed SaaS (Slack, Jira, GitHub, Confluence, etc.) |
| spoof | Spoofy | `intel/spoof.txt` | SPF/DMARC/DKIM spoofability |
| cloud_enum_scan | cloud_enum | `intel/cloud_enum.txt` | AWS S3, Azure Blob, GCP, DO Spaces buckets |

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

### Step 3: Save Intel deliverable

```
wstg_save_deliverable(
  deliverable_type='intel_analysis',
  content=<json or markdown summary of all findings>,
  producer_agent='pintel'
)
```

### Step 4: Track

```
wstg_track_tool(tool_name='pintel', status='run', notes='WHOIS + misconfig-mapper + Spoofy + cloud_enum')
```

## Output

- Files in `runtime/engagements/<eid>/recon/<domain>/intel/`
- `intel_analysis` deliverable consumed by Phase 6 (HUNT) agents for target intelligence

## Notes

- If `whois` is unavailable, domain_info is skipped (system package: `apt install whois`)
- The optional tools (msftrecon, Scopify, Spoofy, cloud_enum) can be installed via `./tools/phase-intel.sh --install`
- Intel results are informational context, not blocking — proceed to Phase 4 (RECON) regardless
