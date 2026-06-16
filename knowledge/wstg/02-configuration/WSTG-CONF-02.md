---
id: WSTG-CONF-02
title: Test Application Platform Configuration
category: Configuration and Deployment Management
severity_range: Low-High
owasp_ref: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration
---

# WSTG-CONF-02: Test Application Platform Configuration

## Summary

Application platform configuration testing evaluates whether the web server, application framework, and associated middleware are configured securely. Default installations often include sample applications, verbose error pages, unnecessary modules, and default credentials that introduce security risks. This test identifies deviations from security hardening best practices.

## Test Objectives

- Identify default or sample applications and files left on the server
- Determine if unnecessary features or modules are enabled
- Assess error handling configuration for information disclosure
- Check for default credentials on application platform components
- Validate that logging and security configurations follow best practices

## Prerequisites

- Web server and application framework have been identified (from WSTG-CONF-01)

## Test Steps

### Step 1: Check for Default and Sample Applications

**CLI Actions:**
1. Use `curl` to probe for common default pages and sample applications:

   For Apache:
   ``
   GET /manual/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /server-status HTTP/1.1
   Host: target.com
   ``
   ``
   GET /server-info HTTP/1.1
   Host: target.com
   ``

   For Apache Tomcat:
   ``
   GET /examples/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /docs/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /manager/html HTTP/1.1
   Host: target.com
   ``
   ``
   GET /host-manager/html HTTP/1.1
   Host: target.com
   ``

   For IIS:
   ``
   GET /iisstart.htm HTTP/1.1
   Host: target.com
   ``
   ``
   GET /iishelp/ HTTP/1.1
   Host: target.com
   ``

   For nginx:
   ``
   GET /nginx_status HTTP/1.1
   Host: target.com
   ``

2. Use `save to manual-review file` for any identified default pages to further investigate the content they expose

### Step 2: Test for Verbose Error Handling

**CLI Actions:**
1. Use `curl` to trigger application errors and check for verbose output:
   ``
   GET /nonexistent-path-xyz123 HTTP/1.1
   Host: target.com
   ``
2. Trigger a server error by sending malformed input:
   ``
   GET /index.php?id=1' HTTP/1.1
   Host: target.com
   ``
   ``
   GET /%00 HTTP/1.1
   Host: target.com
   ``
3. Look for stack traces, framework version numbers, file paths, database connection strings, or internal IP addresses in error responses
4. Check for debug mode indicators in responses (e.g., Django debug page, Laravel debug bar, ASP.NET YSOD)

### Step 3: Identify Unnecessary HTTP Headers and Features

**CLI Actions:**
1. Use `curl` to request the homepage and inspect response headers:
   ``
   GET / HTTP/1.1
   Host: target.com
   ``
2. Check for headers that reveal configuration details:
   - `X-Powered-By` - Framework information
   - `X-AspNet-Version` - ASP.NET version
   - `X-AspNetMvc-Version` - ASP.NET MVC version
   - `X-Runtime` - Ruby on Rails runtime
   - `X-Debug-Token` / `X-Debug-Token-Link` - Symfony debug profiler
3. Use `curl` to review headers across multiple endpoints for inconsistent configuration

### Step 4: Test for Default Credentials

**CLI Actions:**
1. If management interfaces were identified in Step 1, use `curl` to test default credentials:

   For Tomcat Manager:
   ``
   GET /manager/html HTTP/1.1
   Host: target.com
   Authorization: Basic dG9tY2F0OnRvbWNhdA==
   ``
   (tomcat:tomcat in Base64)

2. Use `base64` to encode common default credential pairs:
   - `admin:admin`
   - `admin:password`
   - `admin:` (empty password)
   - `tomcat:s3cret`
   - `manager:manager`

3. Use `ffuf` to automate testing of multiple credential pairs against identified login endpoints

### Step 5: Check for Enabled Debug or Development Features

**CLI Actions:**
1. Use `curl` to probe for common debug endpoints:
   ``
   GET /debug HTTP/1.1
   Host: target.com
   ``
   ``
   GET /phpinfo.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /info.php HTTP/1.1
   Host: target.com
   ``
   ``
   GET /elmah.axd HTTP/1.1
   Host: target.com
   ``
   ``
   GET /trace.axd HTTP/1.1
   Host: target.com
   ``
   ``
   GET /_profiler/ HTTP/1.1
   Host: target.com
   ``
   ``
   GET /actuator HTTP/1.1
   Host: target.com
   ``
   ``
   GET /actuator/env HTTP/1.1
   Host: target.com
   ``
   ``
   GET /actuator/health HTTP/1.1
   Host: target.com
   ``
2. Check for Spring Boot Actuator endpoints that may expose configuration, environment variables, or heap dumps
3. check for any platform-related findings from Burp's active scanner

### Step 6: Review Platform Configuration Files

**CLI Actions:**
1. Use `curl` to attempt to access configuration files directly:
   ``
   GET /web.config HTTP/1.1
   Host: target.com
   ``
   ``
   GET /WEB-INF/web.xml HTTP/1.1
   Host: target.com
   ``
   ``
   GET /.htaccess HTTP/1.1
   Host: target.com
   ``
   ``
   GET /nginx.conf HTTP/1.1
   Host: target.com
   ``
   ``
   GET /application.properties HTTP/1.1
   Host: target.com
   ``
   ``
   GET /application.yml HTTP/1.1
   Host: target.com
   ``
   ``
   GET /appsettings.json HTTP/1.1
   Host: target.com
   ``
2. Any accessible configuration file is a significant finding

## Payloads

### Common Default Application Paths
```
/examples/
/docs/
/manual/
/server-status
/server-info
/manager/html
/host-manager/html
/phpinfo.php
/info.php
/debug
/elmah.axd
/trace.axd
/_profiler/
/actuator
/actuator/env
/actuator/health
/actuator/beans
/actuator/configprops
/actuator/heapdump
/.env
/web.config
/WEB-INF/web.xml
/.htaccess
```

### Default Credential Pairs (username:password)
```
admin:admin
admin:password
admin:123456
tomcat:tomcat
tomcat:s3cret
manager:manager
root:root
```

## Detection Criteria

A finding should be logged when:
- Default or sample applications are accessible in production
- Verbose error pages expose stack traces, file paths, or internal details
- Debug or profiling endpoints are enabled and accessible
- Default credentials are accepted on any management interface
- Configuration files are directly accessible via HTTP
- Unnecessary platform features or modules are enabled
- Information-leaking headers reveal framework or version details

## Severity Assessment

| Condition | Severity |
|-----------|----------|
| Default credentials on management interface | High |
| Configuration files accessible via HTTP containing secrets | High |
| Debug endpoints exposing environment variables or heap dumps | High |
| Verbose error pages showing stack traces and internal paths | Medium |
| Default/sample applications accessible in production | Medium |
| phpinfo() or equivalent exposed | Medium |
| Information-leaking headers (X-Powered-By, X-AspNet-Version) | Low |
| Server status page accessible without sensitive data | Low |

## Remediation

- Remove all default and sample applications before production deployment
- Configure custom error pages that do not reveal internal details
- Disable debug mode and profiling endpoints in production
- Change all default credentials immediately upon installation
- Remove or restrict access to configuration files via HTTP
- Disable unnecessary server modules and features
- Suppress informational response headers that reveal platform details
- Implement a hardening checklist specific to the platform (e.g., CIS Benchmarks)

## References

- [OWASP Testing Guide - Test Application Platform Configuration](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
