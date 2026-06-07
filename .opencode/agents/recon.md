---
description: Pipeline Phase 2 — Full recon: subdomains, live hosts, crawl, params, nuclei, secrets
---

# RECON

Guide the user through recon. For each tool, suggest the command, let them run it and paste results. For additional recon tradecraft, invoke `@web2-recon` or `@offensive-osint` for deeper OSINT gathering, or `@osint-methodology` for structured OSINT workflows.

You can run the combined orchestrated recon via:
- `bash scripts/tools/auto_recon.sh <target>` — runs subdomain_enum + dns_bruteforce + web_crawl + cariddi + nuclei + secrets in sequence
- `bash scripts/tools/recon_engine.sh <target>` — alternative combined recon engine

Or follow the step-by-step order below:

1. **Subdomains**: `bash scripts/tools/subdomain_enum.sh <target>`
   - Call `track_tool('subdomain_enum', 'run', 'N hosts found')` after results
2. **DNS brute-force**: `bash scripts/tools/dns_bruteforce.sh <target>`
   - `track_tool('dns_bruteforce')`
3. **Live host discovery**: `httpx -l recon/<target>/all_subdomains.txt -o recon/<target>/live_hosts.txt`
4. **Web crawl**: `bash scripts/tools/web_crawl.sh -l recon/<target>/live_hosts.txt`
   - `track_tool('web_crawl')`
5. **Parameter extraction**: `bash scripts/tools/param_extract.sh recon/<target>/`
   - `track_tool('param_extract')`
6. **Parameter discovery (deep)**: `bash scripts/tools/param_discovery.sh <target>`
   - `track_tool('param_discovery')`
7. **Cariddi scan** (secrets, endpoints, info disclosure): `bash scripts/tools/cariddi_scan.sh recon/<target>/live_hosts.txt`
   - `track_tool('cariddi')`
8. **Directory brute-force**: `bash scripts/tools/dir_bruteforce.sh <target>`
   - `track_tool('dir_bruteforce')`
9. **403 bypass**: `bash scripts/tools/bypass_403.sh <target>`
   - `track_tool('bypass_403')`
10. **VHost fuzzing**: `bash scripts/tools/vhost_fuzz.sh <target>`
    - `track_tool('vhost_fuzz')`
11. **Cloud recon**: `bash scripts/tools/cloud_recon.sh <target>`
    - `track_tool('cloud_recon')`
12. **Nuclei scan**: `bash scripts/tools/auto_nuclei.sh recon/<target>/live_hosts.txt`
    - `track_tool('nuclei')`
13. **CVE scan**: `bash scripts/tools/cve_scan.sh <target>`
    - `track_tool('cve_scan')`
14. **Secrets validation**: `bash scripts/tools/auto_secrets.sh recon/<target>/`
    - `track_tool('secrets')`
15. **Subdomain takeover scan**: `bash scripts/tools/takeover_scanner.sh <target>`
    - `track_tool('takeover_scanner')`
16. **Zone transfer**: `bash scripts/tools/zone_transfer.sh <target>`
    - `track_tool('zone_transfer')`
17. **GitHub dorks**: `bash scripts/tools/github_dork.sh <target>`
    - `track_tool('github_dork')`

For each result set, call `parse_tool_output()` to get structured summaries.

After all recon is done, ask: "Ready to rank the attack surface? Type `@surface` to proceed."
