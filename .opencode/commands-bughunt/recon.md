---
name: recon
description: Subdomain enum, live host discovery, URL crawl, and attack surface classification
---

# /recon

Run the full recon pipeline on a target and produce a prioritized attack surface.

## What This Does

1. Enumerates subdomains (subdomain_enum.sh — subfinder + assetfinder + findomain)
2. Resolves DNS and finds live hosts (dnsx + httpx with status/title/tech)
3. Crawls URLs (katana deep crawl + waybackurls historical)
4. Classifies URLs by bug class (gf patterns)
5. Outputs prioritized attack surface summary

## Usage

```
/recon target.com
```

Or with specific focus:
```
/recon target.com --focus api
/recon target.com --focus auth
/recon target.com --fast     (skip historical URLs)
```

## Steps

### Step 1: Subdomain Enumeration

```bash
TARGET="$1"
mkdir -p runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET

# crt.sh (certificate transparency — no API key needed)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/subdomains.txt 2>/dev/null || true

# subdomain_enum.sh — subfinder + assetfinder + findomain + dnsx + httpx
bash scripts/tools/subdomain_enum.sh $TARGET

echo "[+] Subdomains: $(find runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/subdomains/ -name '*.txt' -exec cat {} + 2>/dev/null | sort -u | wc -l)"
```

### Step 2: Live Host Discovery

```bash
# DNS resolve + HTTP probe with tech detection
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/subdomains.txt \
  | dnsx -silent \
  | httpx -silent -status-code -title -tech-detect \
  | tee runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/live-hosts.txt

echo "[+] Live hosts: $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/live-hosts.txt)"

# Filter out language/locale subdomains (2-letter codes like fr, ja, zh, hi)
grep -v -E '^https://[a-z]{2}\.' runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/live-hosts.txt \
  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/live-hosts-filtered.txt 2>/dev/null || true
```

### Step 3: URL Crawl

```bash
# Active crawl
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/live-hosts.txt | awk '{print $1}' \
  | katana -d 3 -jc -kf all -silent \
  | anew runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt

# Historical URLs (waybackurls)
echo $TARGET | waybackurls | anew runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt
# gau removed — waymore covers Wayback Machine better; ~/.gau.toml left for manual use

echo "[+] Total URLs: $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt)"
```

### Step 4: Classify URLs

```bash
# Bug class classification — gf patterns
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf xss       > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/xss-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf ssrf      > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/ssrf-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf idor      > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/idor-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf sqli      > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/sqli-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf redirect  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/redirect-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf lfi       > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/lfi-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf rce       > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/rce-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf ssti      > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/ssti-candidates.txt
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | gf interestingparams > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/interesting-candidates.txt

# Open redirect params (extra patterns not in gf)
grep -E "(\?|&)(redirect|next|return|dest|destination|go|forward|target|redir|url|continue|returnTo|returnUrl|callback|out|link)=" \
  runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | anew runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/redirect-candidates.txt

# CORS check candidates
grep -E "(\?|&)(callback|jsonp|cb|_callback)=" runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt \
  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/cors-jsonp-candidates.txt

# Host header / password reset candidates
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | grep -E "/(forgot|reset|password|recovery)" \
  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/host-header-candidates.txt

# File upload candidates
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | grep -E "/(upload|import|attach|file|document|image|avatar|profile)" \
  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/upload-candidates.txt

# API endpoints
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" \
  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/api-endpoints.txt

# Auth/session endpoints
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | grep -E "/(login|logout|signin|signup|register|auth|oauth|sso|token|session)" \
  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/auth-endpoints.txt

# Admin panels
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/live-hosts.txt | awk '{print $1}' | while read host; do
  for path in /admin /admin/ /dashboard /wp-admin /jenkins /grafana /kibana /phpmyadmin /adminer; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$host$path")
    [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "$STATUS $host$path"
  done
done > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/admin-panels.txt

echo "[+] IDOR candidates:    $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/idor-candidates.txt)"
echo "[+] SSRF candidates:    $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/ssrf-candidates.txt)"
echo "[+] LFI candidates:     $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/lfi-candidates.txt)"
echo "[+] Redirect candidates:$(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/redirect-candidates.txt)"
echo "[+] Upload candidates:  $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/upload-candidates.txt)"
echo "[+] API endpoints:      $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/api-endpoints.txt)"
echo "[+] Auth endpoints:     $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/auth-endpoints.txt)"
echo "[+] Admin panels found: $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/admin-panels.txt)"
```

### Step 5: JS Secret Scan

```bash
# Download and scan JS files for secrets
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | grep "\.js$" | head -200 | \
  xargs -I{} curl -s "{}" | \
  grep -oE "(api_key|apikey|secret|password|token|access_key|aws_access|private_key|client_secret)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{10,}" \
  > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/js-secrets.txt

# trufflehog on JS files
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | grep "\.js$" | head -100 | while read jsurl; do
  trufflehog filesystem --json <(curl -s "$jsurl") 2>/dev/null
done >> runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/trufflehog-js.txt

# secretfinder
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/urls.txt | grep "\.js$" | head -50 | while read jsurl; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$jsurl" -o cli 2>/dev/null
done > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/secretfinder.txt

echo "[+] Potential JS secrets: $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/js-secrets.txt)"
```

### Step 7: Subdomain Takeover Check

```bash
# subzy for subdomain takeover
subzy run --targets runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/subdomains.txt \
  --output runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/subzy.txt

echo "[+] Takeover candidates: $(grep -i "VULNERABLE\|takeover" runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/subzy.txt | wc -l)"
```

### Step 8: Source Leak Quick Wins (30 seconds, often Critical)

```bash
# Check highest-value forgotten files — run before any crawling
for PATH in "/.env" "/.env.production" "/.env.local" "/.git/HEAD" \
            "/swagger.json" "/api/swagger.json" "/openapi.json" "/api-docs" \
            "/v1/swagger.json" "/v2/swagger.json" "/api/v1/swagger.json" \
            "/.git/config" "/package.json" "/composer.json" \
            "/actuator" "/actuator/env" "/actuator/heapdump" \
            "/telescope" "/horizon" "/laravel-filemanager" \
            "/build-info.json" "/info.json" "/version.json" \
            "/.DS_Store" "/crossdomain.xml" "/clientaccesspolicy.xml"; do
  STATUS=$(curl -s -o /tmp/sl_recon -w "%{http_code}" --max-time 5 "https://$TARGET$PATH" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    SIZE=$(wc -c < /tmp/sl_recon)
    echo "[+] HIT $STATUS ($SIZE bytes): https://$TARGET$PATH"
  fi
done > runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/source-leaks.txt 2>&1
cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/source-leaks.txt

# Check source maps on main JS bundles
BUILD_ID=$(curl -s "https://$TARGET/" 2>/dev/null | grep -oP '"buildId":"\K[^"]+')
[ -n "$BUILD_ID" ] && echo "[+] Next.js Build ID: $BUILD_ID" | tee -a runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/source-leaks.txt

# Grab main JS and check for sourceMappingURL
curl -s "https://$TARGET/" | grep -oP 'src="(/[^"]*\.js)"' | while read js; do
  MAP=$(curl -s "https://$TARGET${js}" 2>/dev/null | tail -1 | grep -oP 'sourceMappingURL=\K\S+')
  [ -n "$MAP" ] && echo "[+] Source map: $TARGET${js}.map" | tee -a runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/source-leaks.txt
done
```

### Step 9: DNS & TLS Quick Checks

```bash
# SPF / DMARC check (email spoofing potential)
dig TXT $TARGET +short | grep "v=spf1" | tee runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/spf.txt
dig TXT _dmarc.$TARGET +short | tee runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dmarc.txt
[ -z "$(cat runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dmarc.txt)" ] && echo "[!] MISSING DMARC: $TARGET" | tee -a runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dns-issues.txt
grep -q "+all" runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/spf.txt && echo "[CRITICAL] SPF allows +all — email spoofing!" | tee -a runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dns-issues.txt
grep -q "p=none" runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dmarc.txt && echo "[HIGH] DMARC p=none — no enforcement" | tee -a runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dns-issues.txt

# Zone transfer attempt
for NS in $(dig NS $TARGET +short 2>/dev/null); do
  AXFR=$(dig AXFR $TARGET @$NS 2>/dev/null | grep -v "^;" | grep -v "^$")
  [ -n "$AXFR" ] && echo "[CRITICAL] AXFR SUCCESS via $NS" | tee runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/axfr.txt && echo "$AXFR" >> runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/axfr.txt
done

# HSTS check on main domain
HSTS=$(curl -sI "https://$TARGET/" | grep -i "strict-transport-security")
[ -z "$HSTS" ] && echo "[!] MISSING HSTS: $TARGET" | tee -a runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dns-issues.txt

echo "[+] DNS/TLS issues: $(wc -l < runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/$TARGET/dns-issues.txt 2>/dev/null || echo 0)"
```

## Output

After running, you will have in `runtime/engagements/${ENGAGEMENT_ID:-default-engagement}/recon/<target>/`:
```
subdomains.txt              # All discovered subdomains
in-scope-subs.txt           # Subdomains confirmed in scope
live-hosts.txt              # Live hosts with status/title/tech
urls.txt                    # All crawled URLs

# Classified attack surface:
idor-candidates.txt         # URLs with ID parameters
ssrf-candidates.txt         # URLs with URL/host parameters
xss-candidates.txt          # URLs with reflection candidates
sqli-candidates.txt         # URLs with SQL-injectable params
lfi-candidates.txt          # URLs with file-include params
rce-candidates.txt          # URLs with exec/cmd params
ssti-candidates.txt         # URLs with template params
redirect-candidates.txt     # URLs with redirect params
cors-jsonp-candidates.txt   # JSONP/callback endpoints
host-header-candidates.txt  # Password reset / recovery endpoints
upload-candidates.txt       # File upload endpoints
interesting-candidates.txt  # Other interesting params
api-endpoints.txt           # API-specific paths
auth-endpoints.txt          # Login/OAuth/SSO endpoints
admin-panels.txt            # Accessible admin panels

# Automated findings:
js-secrets.txt              # Potential secrets in JS files
trufflehog-js.txt           # trufflehog JS scan results
secretfinder.txt            # SecretFinder scan results
subzy.txt                   # Subdomain takeover candidates
```

## What to Do Next

1. Review `live-hosts.txt` — open interesting ones in browser
2. Review `api-endpoints.txt` — start IDOR testing
3. Check for admin panels: grep live-hosts for `/admin`, `/jenkins`, `/grafana`
4. Run `/hunt target.com` to start active vulnerability testing

## 5-Minute Rule

If after running this pipeline:
- All hosts return 403 or static pages
- No API endpoints visible
- No interesting parameters in URLs

**→ Move on to a different target.**
