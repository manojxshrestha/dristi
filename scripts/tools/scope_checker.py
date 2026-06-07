"""
Deterministic scope checker — code check, not LLM judgment.

Validates URLs against an allowlist of domain patterns before any outbound request.
Uses anchored suffix matching (not raw fnmatch) to prevent subdomain confusion:
  - "*.target.com" matches "sub.target.com" but NOT "evil-target.com"
  - "*-eu.target.com" matches "anything-eu.target.com" but NOT "eu.target.com"
  - "target.com" matches exactly "target.com"

Known limitation: IP addresses and CIDR ranges are NOT supported (returns False + warning).
"""

import json
import sys
from pathlib import Path
from urllib.parse import urlparse


class ScopeChecker:
    """Deterministic scope validator for bug bounty targets."""

    def __init__(
        self,
        domains: list[str],
        excluded_domains: list[str] | None = None,
        excluded_classes: list[str] | None = None,
    ):
        """
        Args:
            domains: Allowlist patterns like ["*.target.com", "*-eu.target.com", "api.target.com"]
            excluded_domains: Blocklist patterns like ["blog.target.com"]
            excluded_classes: Vuln classes excluded by program (e.g., ["dos"])
        """
        self.domains = [d.lower() for d in domains]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_classes = [c.lower() for c in (excluded_classes or [])]

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL's hostname is in scope.

        Returns:
            True if the hostname matches an allowed pattern and is not excluded.
            False otherwise (including for malformed URLs, empty input, IP addresses).
        """
        if not url or not isinstance(url, str):
            return False

        # Ensure we have a scheme for urlparse
        normalized = url if "://" in url else f"https://{url}"

        try:
            parsed = urlparse(normalized)
        except Exception:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        hostname = hostname.lower()

        # IP address check — not supported, return False with warning
        if _is_ip(hostname):
            print(
                f"WARNING: scope checker does not support IP addresses: {hostname}",
                file=sys.stderr,
            )
            return False

        # Check exclusion list first
        for excluded in self.excluded_domains:
            if _domain_matches(hostname, excluded):
                return False

        # Check allowlist
        for pattern in self.domains:
            if _domain_matches(hostname, pattern):
                return True

        return False

    def is_vuln_class_allowed(self, vuln_class: str) -> bool:
        """Check if a vulnerability class is allowed by the program."""
        return vuln_class.lower() not in self.excluded_classes

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a list of URLs into (in_scope, out_of_scope)."""
        in_scope = []
        out_of_scope = []
        for url in urls:
            if self.is_in_scope(url):
                in_scope.append(url)
            else:
                out_of_scope.append(url)
        return in_scope, out_of_scope

    def filter_file(self, input_path: str, output_path: str | None = None) -> tuple[int, int]:
        """Filter a file of URLs (one per line) through scope check.

        Args:
            input_path: Path to file with URLs, one per line.
            output_path: If provided, write in-scope URLs here. If None, filter in-place.

        Returns:
            (in_scope_count, out_of_scope_count)
        """
        with open(input_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        in_scope, out_of_scope = self.filter_urls(lines)

        dest = output_path or input_path
        with open(dest, "w") as f:
            for url in in_scope:
                f.write(url + "\n")

        if out_of_scope:
            print(
                f"WARNING: filtered {len(out_of_scope)} out-of-scope URLs from {input_path}",
                file=sys.stderr,
            )

        return len(in_scope), len(out_of_scope)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Anchored domain matching — prevents subdomain confusion.

    *.target.com        → matches sub.target.com, a.b.target.com
                        → does NOT match target.com, evil-target.com
    *-eu.target.com     → matches foo-eu.target.com, bar-eu.target.com
                        → does NOT match eu.target.com, foo-us.target.com
    target.com          → matches target.com exactly
    """
    if pattern.startswith("*-"):
        # Prefix wildcard: *- prefix matches any subdomain part
        # e.g., *-eu.target.com → suffix: -eu.target.com
        suffix = pattern[1:]  # "-eu.target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    elif pattern.startswith("*."):
        # Subdomain wildcard: must be a proper subdomain
        suffix = pattern[1:]  # ".target.com"
        return hostname.endswith(suffix) and hostname != suffix[1:]
    else:
        # Exact match
        return hostname == pattern


def _is_ip(hostname: str) -> bool:
    """Check if hostname looks like an IP address (v4 or v6)."""
    # IPv6 in brackets
    if hostname.startswith("[") or ":" in hostname:
        return True
    # IPv4
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Filter URLs/subdomains by scope")
    parser.add_argument("--domain", required=True, help="Target domain (engagement ID)")
    parser.add_argument("--input", required=True, help="Input file with URLs/subdomains, one per line")
    parser.add_argument("--output", required=True, help="Output file for in-scope entries")
    parser.add_argument("--excluded", help="Comma-separated list of excluded domains")
    args = parser.parse_args()

    # Read scope from engagement DB
    scope_dir = Path(__file__).parent.parent.parent / "server" / "data" / "scope"
    scope_file = scope_dir / f"{args.domain}.json"

    if not scope_file.exists():
        # No scope registered — pass all through
        with open(args.input) as f:
            lines = [line.strip() for line in f if line.strip()]
        with open(args.output, "w") as f:
            for line in lines:
                f.write(line + "\n")
        print(f"No scope file found. Copied {len(lines)} entries to output (all assumed in-scope).")
        sys.exit(0)

    scope_data = json.loads(scope_file.read_text())

    # Separate domain-based assets from mobile-app assets
    domain_types_that_are_urls = {"app", "auth_provider", "api", "cdn", "wildcard_domain", "url"}

    from urllib.parse import urlparse

    # Helper: extract clean hostname from a domain entry that may contain path or scheme
    def clean_domain(d: str) -> str:
        d = d.strip()
        if d.startswith(('http://', 'https://')):
            parsed = urlparse(d)
            return parsed.hostname or d
        # Remove path — keep only hostname
        if '/' in d:
            return d.split('/')[0]
        return d

    # Build allowlist from eligible domain-type entries
    eligible_domains = [
        clean_domain(entry["domain"])
        for entry in scope_data
        if entry["domain_type"] in domain_types_that_are_urls
        and entry.get("eligibility", "eligible") != "ineligible"
        and entry.get("eligibility", "eligible") != "none"
    ]

    # Build exclusion list: third_party + ineligible entries
    excluded = args.excluded.split(",") if args.excluded else []
    excluded += [
        entry["domain"]
        for entry in scope_data
        if entry["domain_type"] == "third_party"
        or entry.get("eligibility", "eligible") == "ineligible"
        or entry.get("eligibility", "eligible") == "none"
    ]

    # Extract mobile app entries for informational logging
    mobile_apps = [
        entry
        for entry in scope_data
        if entry["domain_type"] in ("android_app", "ios_app")
    ]

    if not eligible_domains and not mobile_apps:
        print("No eligible scope entries found. Check scope registration.", file=sys.stderr)
        sys.exit(1)

    checker = ScopeChecker(domains=eligible_domains, excluded_domains=excluded if excluded else None)

    with open(args.input) as f:
        lines = [line.strip() for line in f if line.strip()]

    in_scope, out_of_scope = checker.filter_urls(lines)

    with open(args.output, "w") as f:
        for url in in_scope:
            f.write(url + "\n")

    if mobile_apps:
        app_summary = "; ".join(f"{a['domain']} ({a['domain_type']})" for a in mobile_apps)
        print(f"NOTE: Mobile app assets in scope — {app_summary}", file=sys.stderr)

    if out_of_scope:
        print(f"Filtered {len(out_of_scope)} out-of-scope entries. {len(in_scope)} in scope.", file=sys.stderr)

    print(f"{len(in_scope)} in-scope entries written to {args.output}")
