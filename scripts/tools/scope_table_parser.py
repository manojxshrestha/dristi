"""
Parse arbitrary scope tables from bug bounty programs into structured scope entries.

Handles:
- Any column layout (dynamic header detection)
- Multi-line entries (descriptions under asset names)
- Mixed asset types: domain, wildcard (*. / *-), Android, iOS, API, URL, third_party
- Eligibility mapping from severity/bounty columns
- Notes/restrictions from description blocks
"""

import json
import re
import sys
from urllib.parse import urlparse


# ── Asset type detection ──────────────────────────────────────────────────────

ANDROID_PACKAGE_RE = re.compile(
    r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
)
IOS_ID_RE = re.compile(r'^\d{6,}$')
WILDCARD_DOT_RE = re.compile(r'^\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
WILDCARD_PREFIX_RE = re.compile(r'^\*-[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
DOMAIN_RE = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
URL_RE = re.compile(r'^https?://', re.IGNORECASE)


KNOWN_TLDS = {
    'com', 'org', 'net', 'io', 'gov', 'edu', 'mil', 'co', 'uk', 'us', 'ca',
    'au', 'de', 'fr', 'jp', 'cn', 'in', 'ru', 'br', 'nl', 'it', 'es', 'ch',
    'se', 'no', 'dk', 'fi', 'pl', 'be', 'at', 'ie', 'nz', 'sg', 'hk', 'kr',
    'tw', 'za', 'mx', 'ar', 'cl', 'co', 'id', 'my', 'ph', 'th', 'vn', 'eg',
    'ng', 'ke', 'ma', 'tz', 'ug',
}


def detect_domain_type(raw: str, type_hint: str = "", notes: str = "") -> str:
    """Detect the domain_type for a scope entry.

    Args:
        raw: The asset name string (domain, package name, app store ID, etc.)
        type_hint: Optional hint from a "Type" column in the table
        notes: Additional context (e.g., "Android: Play Store")

    Returns:
        One of: app, api, android_app, ios_app, wildcard_domain, third_party, url
    """
    raw = raw.strip()
    type_hint = type_hint.strip().lower()
    notes = notes.strip().lower()

    # Explicit type hints (from Type column)
    if type_hint in ('api',):
        return 'api'
    if type_hint in ('url',):
        return 'url'
    if 'android' in type_hint or 'apk' in type_hint:
        return 'android_app'
    if 'ios' in type_hint or 'ipa' in type_hint:
        return 'ios_app'
    if type_hint == 'wildcard':
        return 'wildcard_domain'

    # Notes-based hints
    if 'android' in notes and 'app' in notes:
        return 'android_app'
    if 'ios' in notes and 'app' in notes:
        return 'ios_app'

    # URL detection
    if URL_RE.match(raw):
        return 'url'

    # Wildcard detection
    if raw.startswith('*.') or raw.startswith('*-'):
        return 'wildcard_domain'

    # Check for known domain patterns first
    is_domain = bool(DOMAIN_RE.match(raw))
    is_android = bool(ANDROID_PACKAGE_RE.match(raw))
    is_ios_id = bool(IOS_ID_RE.match(raw))

    # Entry contains a path after domain → likely API endpoint
    if '/' in raw and DOMAIN_RE.match(raw.split('/')[0]):
        return 'api'

    if is_domain and is_android:
        # Ambiguous — could be "com.example.app" (Android) or "sub.example.com" (domain)
        last_segment = raw.rsplit('.', 1)[-1]
        is_known_tld = last_segment in KNOWN_TLDS
        if is_known_tld and raw.split('.')[0] not in ('com', 'org', 'io', 'net', 'co', 'app'):
            # "www.example.com" → domain
            return 'app'
        elif not is_known_tld or raw.split('.')[0] in ('com', 'org', 'io', 'net', 'co', 'app'):
            # "com.example.app" where "app" is not a known TLD → android
            return 'android_app'
        # Default to app
        return 'app'

    if is_domain:
        return 'app'

    # Android package name detection
    if is_android:
        return 'android_app'

    # iOS App Store ID detection
    if is_ios_id:
        return 'ios_app'

    # Fallback
    return 'app'


def detect_wildcard_suffix(pattern: str) -> str:
    """Extract the matching suffix from a wildcard pattern.

    Returns the suffix that a hostname must end with.
    E.g., "*-eu.example.com" → "-eu.example.com"
           "*.example.com" → ".example.com"
    """
    if pattern.startswith('*-'):
        return pattern[1:]  # "-eu.example.com"
    elif pattern.startswith('*.'):
        return pattern[1:]  # ".example.com"
    return pattern


# ── Eligibility mapping from severity column ──────────────────────────────────

SEVERITY_ELIGIBILITY = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'none': 'ineligible',
    'ineligible': 'ineligible',
}


def map_eligibility(severity_str: str) -> str:
    """Map a severity/eligibility value to a structured eligibility level."""
    val = severity_str.strip().lower()
    return SEVERITY_ELIGIBILITY.get(val, 'eligible')


# ── Column detection ──────────────────────────────────────────────────────────

# Known column headers (variations)
ASSET_COL_NAMES = {'asset name', 'asset', 'name', 'domain', 'subdomain', 'host',
                   'application', 'target', 'endpoint', 'url'}
TYPE_COL_NAMES = {'type', 'asset type', 'kind', 'category'}
COVERAGE_COL_NAMES = {'coverage', 'coverage type', 'scope'}
SEVERITY_COL_NAMES = {'max. severity', 'max severity', 'severity', 'maximum severity',
                      'criticality', 'priority', 'severity level', 'severity max'}
BOUNTY_COL_NAMES = {'bounty', 'reward', 'bounty range', 'avg. bounty', 'payout', 'min bounty', 'max bounty'}
ELIGIBILITY_COL_NAMES = {'eligible', 'bounty eligible', 'eligibility', 'bounty'}
NOTES_COL_NAMES = {'notes', 'description', 'details', 'info', 'additional info',
                   'instructions', 'policy'}


def detect_columns(header_tokens: list[str]) -> dict:
    """Detect which column index corresponds to which role.

    Returns dict like: {asset: 0, type: 1, severity: 3, eligibility: 4}
    """
    cols = {}
    for i, tok in enumerate(header_tokens):
        t = tok.lower().strip()
        if not cols.get('asset') and any(n in t for n in ASSET_COL_NAMES):
            cols['asset'] = i
        elif not cols.get('type') and any(n in t for n in TYPE_COL_NAMES):
            cols['type'] = i
        elif not cols.get('coverage') and any(n in t for n in COVERAGE_COL_NAMES):
            cols['coverage'] = i
        elif not cols.get('severity') and any(n in t for n in SEVERITY_COL_NAMES):
            cols['severity'] = i
        elif not cols.get('bounty') and any(n in t for n in BOUNTY_COL_NAMES):
            cols['bounty'] = i
        elif not cols.get('eligible') and any(n in t for n in ELIGIBILITY_COL_NAMES):
            cols['eligible'] = i
        elif not cols.get('notes') and any(n in t for n in NOTES_COL_NAMES):
            cols['notes'] = i
    return cols


# ── Table splitting ───────────────────────────────────────────────────────────

def looks_like_asset(token: str) -> bool:
    """Check if a token looks like a new scope entry (domain, URL, package name, etc.)."""
    token = token.strip()
    if not token:
        return False
    # URL
    if URL_RE.match(token):
        return True
    # Wildcard
    if token.startswith('*.') or token.startswith('*-'):
        return True
    # Domain
    if DOMAIN_RE.match(token):
        return True
    # Domain with path (API endpoint)
    if '/' in token:
        domain_part = token.split('/')[0]
        if DOMAIN_RE.match(domain_part):
            return True
    # Android package (com.example.app)
    if ANDROID_PACKAGE_RE.match(token) and token.count('.') >= 2:
        return True
    # iOS app store ID
    if IOS_ID_RE.match(token):
        return True
    return False


def split_rows(text: str) -> list[list[str]]:
    """Split pasted table text into rows of token lists.

    Handles tab-separated and space-aligned columns.
    Returns raw rows — multi-line entries are NOT merged here.
    """
    lines = text.strip().split('\n')

    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if '\t' in line:
            parts = line.split('\t')
        elif re.search(r'  {3,}', line):
            parts = [p.strip() for p in re.split(r'  {3,}', line) if p.strip()]
        else:
            parts = [line]
        rows.append(parts)

    return rows


def merge_multi_line_entries(rows: list[list[str]]) -> list[list[str]]:
    """Merge continuation lines into their parent entry.

    A continuation is a row whose first token does NOT look like
    a new asset (domain, URL, package name).

    For a continuation row with structured data (tabs):
      - The first token is description text.
      - The remaining tokens (starting from index 1) are the actual
        structured columns matching the header.

    The merge prepends the description to the previous row's first
    column (separated by ' ‖ ') so the main parser can extract both.
    """
    merged = []
    for row in rows:
        first = row[0].strip() if row else ''

        if not merged:
            merged.append(row)
            continue

        if looks_like_asset(first):
            merged.append(row)
            continue

        # Continuation line
        prev = merged[-1]

        if len(row) >= 2:
            # Has structured columns — first token is description,
            # rest are the actual column values matching the header
            # Prepend description to prev[0] and add columns
            if len(prev) == 1:
                # Previous was just the asset name — description goes in
                # prev[0] as "asset ‖ description", columns from row[1:]
                prev[0] = prev[0] + ' ‖ ' + first
                for col_val in row[1:]:
                    prev.append(col_val)
            else:
                # Previous already has columns — description goes in
                # prev[0] as "asset ‖ description", extra columns fill gaps
                prev[0] = prev[0] + ' ‖ ' + first
                for j in range(1, len(row)):
                    if j < len(prev):
                        if (not prev[j].strip() or prev[j] == '') and row[j].strip():
                            prev[j] = row[j]
                    else:
                        prev.append(row[j])
        else:
            # Bare text continuation — append with separator
            prev[0] = prev[0] + ' ‖ ' + first

    return merged


# ── Output normalization ──────────────────────────────────────────────────────

def parse_bounty_range(val: str) -> tuple[float | None, float | None]:
    """Parse a bounty range like '$100 – $250' or '$300'."""
    val = val.strip()
    if not val or val == 'n/a':
        return None, None
    nums = re.findall(r'\$?([\d,]+)', val.replace(',', ''))
    amounts = [float(n) for n in nums]
    if len(amounts) >= 2:
        return amounts[0], amounts[1]
    elif len(amounts) == 1:
        return amounts[0], amounts[0]
    return None, None


def extract_app_id(raw: str, domain_type: str) -> str:
    """Extract the app store ID for mobile apps."""
    if domain_type == 'ios_app' and IOS_ID_RE.match(raw):
        return raw
    if domain_type == 'android_app' and ANDROID_PACKAGE_RE.match(raw):
        return raw
    return ''


def normalize_domain(raw: str) -> str:
    """Normalize an asset name to a clean domain/identifier."""
    raw = raw.strip().rstrip('/')
    # Remove URL scheme if present
    if URL_RE.match(raw):
        parsed = urlparse(raw)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        if path and path != '/':
            return hostname + path.rstrip('/')
        return hostname
    return raw


def extract_asset_name(raw: str) -> tuple[str, str]:
    """Separate a clean asset name from trailing description text.

    Uses ' ‖ ' separator set by merge_multi_line_entries().
    Falls back to regex-based extraction if no separator found.

    Returns: (asset_name, description)
    """
    raw = raw.strip()
    if not raw:
        return '', ''

    # Check for structured separator from merge
    if ' ‖ ' in raw:
        parts = raw.split(' ‖ ', 1)
        return parts[0].strip(), parts[1].strip()

    # Try to extract URL at start
    url_match = re.match(r'(https?://\S+)', raw)
    if url_match:
        url = url_match.group(1)
        rest = raw[url_match.end():].strip()
        return normalize_domain(url), rest

    # Try to extract wildcard at start
    wildcard_match = re.match(r'(\*[.-][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', raw)
    if wildcard_match:
        domain = wildcard_match.group(1)
        rest = raw[wildcard_match.end():].strip()
        return domain, rest

    # Try to extract domain at start
    domain_match = re.match(
        r'([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}(/[^\s]*)?)',
        raw
    )
    if domain_match:
        domain = domain_match.group(1)
        rest = raw[domain_match.end():].strip()
        return domain, rest

    # Try to extract Android package at start
    pkg_match = re.match(r'([a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,})', raw)
    if pkg_match:
        pkg = pkg_match.group(1)
        rest = raw[pkg_match.end():].strip()
        return pkg, rest

    # Try to extract iOS numeric ID at start
    id_match = re.match(r'(\d{6,})', raw)
    if id_match:
        return id_match.group(1), raw[id_match.end():].strip()

    return raw, ''


# ── Main parser ───────────────────────────────────────────────────────────────

def parse_scope_table(text: str) -> list[dict]:
    """Parse a pasted scope table into structured scope entries.

    Args:
        text: The full pasted text (e.g., from HackerOne scope page)

    Returns:
        List of dicts with keys: domain, domain_type, eligibility, notes, app_id
    """
    rows = split_rows(text)
    if not rows:
        return []

    # Detect header row
    # Look for the row that best matches column headers
    header_idx = None
    for i, row in enumerate(rows):
        joined = ' '.join(row).lower()
        matches = sum(1 for n in ASSET_COL_NAMES | SEVERITY_COL_NAMES | TYPE_COL_NAMES
                      if n in joined)
        if matches >= 2 and i <= 3:
            header_idx = i
            break

    if header_idx is None:
        # No header found — assume first row is data
        # Try to auto-detect columns from data patterns
        col_count = max(len(r) for r in rows)
        header_tokens = [f"col_{i}" for i in range(col_count)]
        data_start = 0
        cols = {}
    else:
        header_tokens = rows[header_idx]
        data_start = header_idx + 1
        cols = detect_columns(header_tokens)

    data_rows = rows[data_start:]
    data_rows = merge_multi_line_entries(data_rows)

    entries = []
    for row in data_rows:
        if not row:
            continue

        raw_asset = row[0] if row else ''
        if not raw_asset.strip():
            continue

        # Skip summary/pagination lines at the bottom
        if any(kw in raw_asset.lower() for kw in
               ('rewards summary', 'total', 'subtotal', 'page', 'showing',
                'out of scope', 'scope exclusions', 'last updated')):
            continue

        # Clean domain from any merged description text
        asset, extracted_desc = extract_asset_name(raw_asset)

        # Extract values by detected columns
        type_hint = ''
        if 'type' in cols and cols['type'] < len(row):
            type_hint = row[cols['type']]

        severity = 'None'
        if 'severity' in cols and cols['severity'] < len(row):
            severity = row[cols['severity']]
        elif 'eligible' in cols and cols['eligible'] < len(row):
            # Use eligibility column as severity proxy
            severity = row[cols['eligible']]
        elif 'bounty' in cols and cols['bounty'] < len(row):
            bounty_raw = row[cols['bounty']]
            if bounty_raw.strip().lower() in ('ineligible', 'none', 'n/a'):
                severity = 'None'
            else:
                severity = 'Eligible'

        eligibility = map_eligibility(severity)

        # Build notes from available columns
        notes_parts = []
        if extracted_desc:
            notes_parts.append(extracted_desc)
        if type_hint and type_hint not in ('Domain', 'Wildcard', 'API', 'URL',
                                            'Android: .apk', 'iOS: .ipa'):
            notes_parts.append(type_hint)

        # Extracted notes column
        if 'notes' in cols and cols['notes'] < len(row):
            notes_parts.append(row[cols['notes']])

        # Any extra tokens beyond detected columns get appended to notes
        if 'severity' in cols and len(row) > max(cols.values()) + 1:
            extra = ' '.join(str(row[i]) for i in range(max(cols.values()) + 1, len(row)) if row[i].strip())
            if extra:
                notes_parts.append(extra)

        notes = '. '.join(p for p in notes_parts if p.strip())

        # Detect bounty range if available
        bounty_min, bounty_max = None, None
        if 'bounty' in cols and cols['bounty'] < len(row):
            bounty_min, bounty_max = parse_bounty_range(row[cols['bounty']])

        domain_type = detect_domain_type(asset, type_hint, notes)
        app_id = extract_app_id(asset, domain_type)

        entry = {
            'domain': asset,
            'domain_type': domain_type,
            'eligibility': eligibility,
            'notes': notes,
        }
        if app_id:
            entry['app_id'] = app_id
        if bounty_min is not None:
            entry['bounty_min'] = bounty_min
            entry['bounty_max'] = bounty_max

        entries.append(entry)

    return entries


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Parse a bug bounty scope table into structured JSON scope entries.'
    )
    parser.add_argument('--input', '-i', help='Input file with scope table text')
    parser.add_argument('--output', '-o', help='Output JSON file (default: stdout)')
    parser.add_argument('--pretty', action='store_true', default=True,
                        help='Pretty-print JSON output (default: true)')

    args = parser.parse_args()

    if args.input:
        with open(args.input, 'r', encoding='utf-8') as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    entries = parse_scope_table(text)

    indent = 2 if args.pretty else None
    output = json.dumps(entries, indent=indent, ensure_ascii=False)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Wrote {len(entries)} scope entries to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
