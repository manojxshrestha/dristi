#!/usr/bin/env bash
# =============================================================================
# generate_poc_report.sh — Generate per-finding PoC report template
#
# Reads a finding from the SQLite database + evidence files, fills the
# template from templates/poc-report-template.md with available data.
#
# Usage:
#   generate_poc_report.sh <engagement-id> <finding-id>
#   generate_poc_report.sh <engagement-id> all
#
# Output:
#   runtime/engagements/<eid>/evidence/<finding-id>/poc-report.md
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
source "$TOOLS_DIR/_env.sh"

EID="${1:?Usage: $0 <engagement-id> <finding-id|all>}"
FINDING_FILTER="${2:?Usage: $0 <engagement-id> <finding-id|all>}"
DB_PATH="${DRISTI_ROOT:-.}/server/data/findings.db"
EVIDENCE_BASE="${DRISTI_ROOT:-.}/runtime/engagements/${EID}/evidence"

if [ ! -f "$DB_PATH" ]; then
  log_err "Findings database not found at $DB_PATH"
  exit 1
fi

generate_for_finding() {
  local FINDING_ID="$1"
  local EVIDENCE_DIR="$EVIDENCE_BASE/$FINDING_ID"
  mkdir -p "$EVIDENCE_DIR"

  python3 << PYEOF
import sqlite3, json, os, glob

EID = '$EID'
FINDING_ID = int('$FINDING_ID')
DB_PATH = '$DB_PATH'
EVIDENCE_DIR = '$EVIDENCE_DIR'

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Get finding
cursor = conn.execute(
    'SELECT id, engagement_id, title, severity, cvss, cve, mitre_id, test_id, '
    'tool_used, status, poc_output, affected_url, affected_parameter, '
    'description, evidence, remediation, domain, created_at, updated_at, finding_ref '
    'FROM vulns WHERE id = ? AND engagement_id = ?',
    (FINDING_ID, EID)
)
row = cursor.fetchone()
if not row:
    print(f"ERROR: Finding {FINDING_ID} not found", flush=True)
    exit(1)

finding = dict(row)
conn.close()

finding_ref = finding.get("finding_ref") or f"FINDING-{finding['id']:03d}"

# Collect evidence files
screenshots = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "screenshot.*")))
request_logs = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "request.*")))
collab_files = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "collaborator*.*")))

# Build supporting material list
supporting = []
for f in screenshots:
    supporting.append(f"  * \`{os.path.basename(f)}\` — PoC screenshot")
for f in request_logs:
    supporting.append(f"  * \`{os.path.basename(f)}\` — HTTP request/response")
for f in collab_files:
    supporting.append(f"  * \`{os.path.basename(f)}\` — Collaborator interaction")
if not supporting:
    supporting.append("  * [attachment / reference]")

# Build sections
summary = finding["description"] or "[add summary of the vulnerability]"

shops = ""
if finding["domain"]:
    shops = finding["domain"]
else:
    shops = "[add list of <shop>.myshopify.com domains here, if applicable]"

request_ids = "[add list of Request ID values (found in X-Request-ID response header)]"

steps = ""
poc = finding["poc_output"] or finding["evidence"] or ""
if poc:
    steps = poc.strip()
    # Ensure it looks like numbered steps
    if not steps.startswith("1."):
        steps = f"  1. {steps}"
else:
    steps = "[add details for how we can reproduce the issue]\n\n  1. [add step]\n  2. [add step]"

supporting_text = "\n".join(supporting)

# Render template
template = f"""## Summary:
{summary}

## Shops Used to Test:
{shops}

## Relevant Request IDs:
{request_ids}

## Steps To Reproduce:
{steps}

## Supporting Material:
{supporting_text}
"""

poc_path = os.path.join(EVIDENCE_DIR, "poc-report.md")
with open(poc_path, "w") as f:
    f.write(template)

print(f"  {finding_ref}: {finding['title']} [{finding['severity']}] → poc-report.md")
PYEOF
}

# ── Main ────────────────────────────────────────────────────────────────────
if [ "$FINDING_FILTER" = "all" ]; then
  log_info "Generating PoC reports for all findings in $EID"
  FINDINGS=$(python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.execute('SELECT id FROM vulns WHERE engagement_id = ?', ('$EID',))
ids = [str(r[0]) for r in cursor.fetchall()]
conn.close()
print(' '.join(ids))
")
  if [ -z "$FINDINGS" ]; then
    log_warn "No findings found for engagement $EID"
    exit 0
  fi
  for fid in $FINDINGS; do
    generate_for_finding "$fid" || true
  done
  log_ok "Done. PoC reports generated for all findings."
else
  generate_for_finding "$FINDING_FILTER"
  log_ok "PoC report generated for finding $FINDING_FILTER"
fi
