---
id: WSTG-ATHN-02
title: Testing for Default Credentials
category: Authentication
severity_range: Medium-Critical
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials
---

# WSTG-ATHN-02: Testing for Default Credentials

## Summary

Many web applications and appliances ship with default credentials that are well-documented. Administrators often fail to change these defaults, leaving systems vulnerable to unauthorized access.

## Test Objectives

- Identify default or common credentials for the target application
- Test if default credentials allow authentication
- Check for default credentials on administrative interfaces

## Prerequisites

- Target application login page is identified
- Application/framework type has been fingerprinted (WSTG-INFO-02, WSTG-INFO-08)

## Test Steps

### Step 1: Identify Application Type

**CLI Actions:**
1. Use `curl` to review past requests and identify the application type
2. Use `curl` to check for common admin paths:
   ``
   GET /admin/ HTTP/1.1
   GET /administrator/ HTTP/1.1
   GET /wp-admin/ HTTP/1.1
   GET /manager/html HTTP/1.1
   GET /phpmyadmin/ HTTP/1.1
   ``

### Step 2: Test Default Credentials

**CLI Actions:**
For each identified login page, use `curl` to attempt login with common default credentials:

### Step 3: Test with Burp Intruder

**CLI Actions:**
1. Use `save to manual-review file` with the login request for manual testing
2. Use `ffuf` for automated credential testing against the login endpoint

## Payloads

### Common Default Credentials
```
admin:admin
admin:password
admin:admin123
admin:12345
administrator:administrator
root:root
root:toor
root:password
test:test
guest:guest
user:user
demo:demo
```

### Application-Specific Defaults
```
# Apache Tomcat
tomcat:tomcat
admin:tomcat
tomcat:s3cret
manager:manager

# WordPress
admin:admin
admin:password

# Joomla
admin:admin

# phpMyAdmin
root:(empty)
root:root
root:mysql

# Jenkins
admin:admin
admin:password

# Grafana
admin:admin

# Elasticsearch
elastic:changeme

# MongoDB
(no auth by default)

# Redis
(no auth by default)

# RabbitMQ
guest:guest

# PostgreSQL
postgres:postgres

# MySQL
root:(empty)
root:root

# Spring Boot Actuator
user:password (check /actuator endpoints)

# Default router/appliance
admin:admin
admin:password
admin:1234
```

### Automated Default Credential Testing with hydra

**CLI Actions:**
Use `hydra` to test common default credentials against login forms:

```bash
# HTTP POST form login

# HTTP Basic Auth
```

Adjust the form parameters (`username`, `password`, failure string `F=Invalid`) based on the actual login endpoint. Use `-t 4` to limit parallel tasks and avoid triggering rate limits.

Common default credential pairs to test: `admin:admin`, `admin:password`, `root:root`, `admin:12345`, `guest:guest`, `admin:changeme`.

## Detection Criteria

A finding should be logged when:
- Default credentials allow successful authentication
- Default admin accounts exist and are accessible
- Default service accounts have not been changed
- Password-less accounts are accessible

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Default admin credentials grant full application access | Critical |
| Default credentials access limited functionality | High |
| Default credentials for non-critical services | Medium |
| Default account exists but password has been changed | Informational |

## Remediation

- Change all default credentials immediately upon deployment
- Disable or remove default accounts that are not needed
- Implement account lockout after failed login attempts
- Force password change on first login for default accounts
- Use strong, unique passwords for all accounts
- Regularly audit for default credentials in infrastructure

## References

- [OWASP Testing Guide - Default Credentials](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CIRT Default Password Database](https://www.cirt.net/passwords)
