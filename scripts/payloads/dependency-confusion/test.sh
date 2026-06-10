#!/bin/bash
# Dependency Confusion test: scan for package files and check if packages exist on public registries
# Note: This is more of a recon/lookup operation than a curl-to-target test
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib.sh"
CLASS=dependency-confusion
ENGAGEMENT="${1:?Usage: $0 <engagement-id> [target-dir]}"
TARGET_DIR="${2:-$BASE_DIR/engagements/$ENGAGEMENT/recon/files}"
HITS_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon/hits/$CLASS"
mkdir -p "$HITS_DIR"
pat_ref "$CLASS"

info "Scanning for package files in subdomain recon output..."
RECON_DIR="$BASE_DIR/engagements/$ENGAGEMENT/recon"
FOUND=0; TOTAL=0

# Search for package files in subdomain content directories
for dir in "$RECON_DIR"/*/; do
  [ ! -d "$dir" ] && continue
  for pkg_file in package.json composer.json requirements.txt pom.xml Gemfile go.mod; do
    found=$(find "$dir" -name "$pkg_file" -maxdepth 3 2>/dev/null | head -5)
    for f in $found; do
      TOTAL=$((TOTAL + 1))
      rel="${f#$RECON_DIR/}"
      dest="$HITS_DIR/$(echo "$rel" | tr '/' '_')"
      cp "$f" "$dest" 2>/dev/null || true
      log "Found: $rel"
      
      # Extract package names from each file type
      case "$pkg_file" in
        package.json)
          deps=$(python3 -c "
import json,sys
with open('$f') as fh:
    d = json.load(fh)
deps = set()
for k in ['dependencies', 'devDependencies', 'peerDependencies']:
    deps.update(d.get(k, {}).keys())
for p in sorted(deps):
    if not p.startswith('@'):
        print(p)" 2>/dev/null || true)
          echo "$deps" > "$dest.deps.txt"
          echo "$deps" >> "$HITS_DIR/all_packages.txt" 2>/dev/null
          ;;
        requirements.txt)
          cp "$f" "$dest.txt" 2>/dev/null || true
          cat "$f" >> "$HITS_DIR/all_packages.txt" 2>/dev/null
          ;;
        composer.json)
          deps=$(python3 -c "
import json,sys
with open('$f') as fh:
    d = json.load(fh)
for k in ['require', 'require-dev']:
    for p in d.get(k, {}):
        print(p)" 2>/dev/null || true)
          echo "$deps" > "$dest.deps.txt"
          echo "$deps" >> "$HITS_DIR/all_packages.txt" 2>/dev/null
          ;;
      esac
      FOUND=$((FOUND + 1))
    done
  done
done

if [ -f "$HITS_DIR/all_packages.txt" ]; then
  sort -u "$HITS_DIR/all_packages.txt" -o "$HITS_DIR/all_packages.txt"
  PKG_COUNT=$(wc -l < "$HITS_DIR/all_packages.txt")
  log "Found $FOUND package files with $PKG_COUNT unique packages"
  info "To check for dependency confusion, use 'confused' tool:"
  info "  confused --input $HITS_DIR/all_packages.txt"
else
  info "No package files found in $RECON_DIR"
fi
