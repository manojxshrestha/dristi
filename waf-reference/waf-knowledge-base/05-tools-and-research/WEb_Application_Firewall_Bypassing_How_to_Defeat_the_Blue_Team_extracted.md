---
id: PRESENTATIONS-WEb_Application_Firewall_Bypas
title: WEb Application Firewall Bypassing (How to Defeat the Blue Team).pdf
category: Conference Presentations
severity_range: Informational
source_file: presentations/WEb Application Firewall Bypassing (How to Defeat the Blue Team).pdf
---

# WEb Application Firewall Bypassing (How to Defeat the Blue Team).pdf

**Category:** Conference Presentation
**File:** presentations/WEb Application Firewall Bypassing (How to Defeat the Blue Team).pdf

## Extracted Content

Web 
Web Application
ApplicationFirewall 
Firewall Bypas
Bypassing–
–
how to defeat the blue team
KHALIL BIJJOU
CYBER RISK SERVICES
DELOITTE
29th Octobre 2015
STRUCTURE
STRUCTURE
• Motivation & Objective
• Introduction to Web Application Firewalls
• Bypassing Methods and Techniques
• Approach for Penetration Testers
• The Tool WAFNinja
• Results
• Conclusion
Motivation & 
Motivation & Objective
Objective
MOTIVATION AND THESIS OBJECTIVE (
MOTIVATION AND THESIS OBJECTIVE (I)
I)MOTIVATION
MOTIVATION
• Number of deployed Web Application Firewalls (WAFs) is 
increasing
• WAFs make a penetration test more difficult
• Attempting to bypass a WAF is an important aspect of a 
penetration test
MOTIVATION AND THESIS 
MOTIVATION AND THESIS OBJECTIVE (II)
OBJECTIVE (II)OBJECTIVE
OBJECTIVE
Provide a practical approach for penetration testers which helps
to ensure accurate results
Introduction to Web 
Introduction to Web Applicati
Application Firewalls
Firewalls
INTRODUCTION TO WEB APPLICATION 
INTRODUCTION TO WEB APPLICATION FIREWALLS (I) 
FIREWALLS (I) OVERVIEW
OVERVIEW
• Protects a web application by adding a security layer
• Stands between a user and a web server
• Understands HTTP traffic better than traditional firewalls
• Checks for malicious traffic and blocks it
INTRODUCTION TO WEB APPLICATION 
INTRODUCTION TO WEB APPLICATION FIREWALLS (IV) 
FIREWALLS (IV) FUNCTIONALITY
FUNCTIONALITY
Pre-processor:
Decide wether a 
request will be
processed further
Normalization:
Standardize
user input
Validate Input:
Check user
input against
policies
INTRODUCTION TO WEB APPLICATION 
INTRODUCTION TO WEB APPLICATION FIREWALLS (V) 
FIREWALLS (V) NORMALIZATION
NORMALIZATIONFUNCTIONS
FUNCTIONS
• Simplifies the writing of rules
• No Knowledge about different forms of input needed
compressWhitespace
converts whitespace chars to spaces
hexDecode
decodes a hex-encoded string
lowercase
converts characters to lowercase
urlDecode
decodes a URL-encoded string
INTRODUCTION TO WEB APPLICATION 
INTRODUCTION TO WEB APPLICATION FIREWALLS (VI) 
FIREWALLS (VI) INPUT VALIDATION
INPUT VALIDATION
• Security Models define how to enforce policies
• Policies consist of regular expressions
• Three Security Models:
1.
Positive Security Model
2.
Negative Security Model
3.
Hybrid Security Model
INTRODUCTION TO WEB APPLICATION 
INTRODUCTION TO WEB APPLICATION FIREWALLS (VII)
FIREWALLS (VII) INPUT VALIDATION
INPUT VALIDATION
Positive Security Model (Whitelist)
Negative Security Model (Blacklist)
Deny all but known good
Allow all but known bad
Prevents Zero-day Exploits
Shipped with WAF
More secure than blacklist
Fast adoption
Comprehensive understanding of 
application is needed
Little knowledge needed
Creating policies is a time-consuming
process
Protect several applications
Tends to false positives
Resource-consuming
Bypassing Methods and 
Bypassing Methods and Techni
Techniques
BYPASSING METHODS AND 
BYPASSING METHODS AND TECHNIQUES (I)
TECHNIQUES (I)OVERVIE
OVERVIEW
Pre-processor
Exploitation:
Make WAF skip
input validation
Impedance
Mismatch:
WAF interprets
input differently
than back end
Rule Set 
Bypassing:
Use Payloads that
are not detected by
the WAF
Pre
Pre-processor Exploitation
processor Exploitation
BYPASSING METHODS AND 
BYPASSING METHODS AND TECHNIQUES (II)
TECHNIQUES (II)BYPASSIN
BYPASSING PARAMETER VERIFICATION
• PHP removes whitespaces from parameter names or transforms
them into underscores
• ASP removes % character that is not followed by two 
hexadecimal digits
• A WAF which does not reject unknown parameters may be 
bypassed with this technique.
http://www.website.com/products.php?%20productid=select 1,2,3
http://www.website.com/products.aspx?%productid=select 1,2,3
BYPASSING METHODS AND 
BYPASSING METHODS AND TECHNIQUES (III)
TECHNIQUES (III)PRE
PRE-PROCESSOR EXPLOITATION EXAMPLE
PROCESSOR EXPLOITATION EXAMPLE
X-* Headers
• WAF may be configured to trust certain internal IP Addresses
• Input validation is not applied on requests originating from these IPs
• If WAF retrieves these IPs from headers which can be changed by a user a 
bypass may occur
• A user is in control of the following HTTP Headers:
X-Originating-IP
X-Forwarded-For
X-Remote-IP
X-Remote-Addr
BYPASSING METHODS AND 
BYPASSING METHODS AND TECHNIQUES (IV)
TECHNIQUES (IV)MALFORM
MALFORMED HTTP METHOD
• Misconfigured web servers may accept malformed HTTP 
methods
• A WAF that only inspects GET and POST requests may be
bypassed
BYPASSING METHODS AND 
BYPASSING METHODS AND TECHNIQUES (V)
TECHNIQUES (V)OVERLOAD
OVERLOADING THE WAF
• A WAF may be configured to skip input validation if performance
load is heavy
• Often applies to embedded WAFs
• Great deal of malicious requests can be sent with the chance that
the WAF will overload and skip some requests
Impedance Mismatch
Impedance Mismatch
BYPASSING METHODS AND TECHNIQUES (VI)
BYPASSING METHODS AND TECHNIQUES (VI)HTTP PA
HTTP PARAMETER POLLUTION
• Sending a number of parameters with the same name
• Technologies interpret this request
differently:
Back end
Behavior
Processed
ASP.NET
Concatenate with comma
productid=1,2
JSP
First Occurrence
productid=1
PHP
Last Occurrence
productid=2
http://www.website.com/products/?productid=1&productid=2
BYPASSING METHODS AND 
BYPASSING METHODS AND TECHNIQUES (VII)
TECHNIQUES (VII)IMPEDA
IMPEDANCE MISMATCH EXAMPLE
The following payload
can be divided:
• WAF sees two individual parameters and may not detect the 
payload
• ASP.NET back end concatenates both values
?productid=select 1,2,3 from table
?productid=select 1&productid=2,3 from table
BYPASSING METHODS AND TECHNIQUES (VIII)
BYPASSING METHODS AND TECHNIQUES (VIII)HTTP P
HTTP PARAMETER FRAGMENTATION
• Splitting subsequent code between different parameters
• Example query:
• The following request:
would result in this SQL Query:
sql = "SELECT * FROM table WHERE uid = "+$_GET['uid']+" and pid = +$_GET[‘pid']“ 
http://www.website.com/index.php?uid=1+union/*&pid=*/select 1,2,3
sql = "SELECT * FROM table WHERE uid = 1 union/* and pid = */select 1,2,3"
BYPASSING METHODS AND TECHNIQUES (IX)
BYPASSING METHODS AND TECHNIQUES (IX)DOUBLE 
DOUBLE URL ENCODING
• WAF normalizes URL encoded characters into ASCII text
• The WAF may be configured to decode characters only once
• Double URL Encoding a payload may result in a bypass
• The following payload contains a double URL encoded character
’s’ -> %73 -> %25%37%33
1 union %25%37%33elect 1,2,3
Rule Set Bypassing
Rule Set Bypassing
BYPASSING METHODS AND 
BYPASSING METHODS AND TECHNIQUES (X)
TECHNIQUES (X)BYPASS R
BYPASS RULE SET
• Two methods:
Brute force by enumerating payloads 
Reverse-engineer the WAFs rule set
APPROACH 
APPROACH FOR
FORPENETRATION 
PENETRATION TESTERS
APPROACH 
APPROACH FOR
FORPENETRATION 
PENETRATION TESTERS 
TESTERS (I)
(I)OVERVIE
OVERVIEW
• Similar to the phases of a penetration test
• Divided into six phases, whereas Phase 0 may not always be 
possible
APPROACH 
APPROACH FOR
FORPENETRATION TESTERS
PENETRATION TESTERS(II)
(II)PHASE 0
PHASE 0
Identifying vulnerabilities with a disabled WAF
Objective: find security flaws in the application more easily
assessment of the security level of an application is more accurate
• Allows a more focused approach when the WAF is enabled
• May not be realizable in some penetration tests
APPROACH 
APPROACH FOR
FORPENETRATION TESTERS
PENETRATION TESTERS(III)
(III)PHASE 1
PHASE 1
Reconaissance
Objective: Gather information to get a good overview of the target
• Basis for the subsequent phases
• Gather information about:
web server 
programming language 
WAF & Security Model
Internal IP Addresses
APPROACH 
APPROACH FOR
FORPENETRATION 
PENETRATION TESTERS 
TESTERS (IV)
(IV)PHASE 
PHASE 2
Attacking the pre-processor
Objective: make the WAF skip input validation
• Identify which parts of a HTTP request are inspected by the WAF 
to develop an exploit:
1. Send individual requests that differ in the location of a payload
2. Observe which requests are blocked
3. Attempt to develop an exploit
APPROACH 
APPROACH FOR
FORPENETRATION TESTERS
PENETRATION TESTERS(V)
(V)PHASE 3
PHASE 3
Attempting an impedance mismatch
Objective: make the WAF interpret a request differently than the 
back end and therefore not detecting it
• Knowledge about back end technologies is needed
APPROACH 
APPROACH FOR
FORPENETRATION TESTERS
PENETRATION TESTERS(VI)
(VI)PHASE 4
PHASE 4
Bypassing the rule set
Objective: find a payload that is not blocked by the WAFs rule set
1. Brute force by sending different payloads
2. Reverse-engineer the rule set in a trial and error approach:
1.
Send symbols and keywords that may be useful to craft a payload
2.
Observe which are blocked
3.
Attempt to develop an exploit based on the results of the previous steps
APPROACH 
APPROACH FOR
FORPENETRATION TESTERS
PENETRATION TESTERS(VII)
(VII)PHASE 
PHASE 5
Identifying miscellaneous vulnerabilities
Objective: find other vulnerabilities that can not be detected by the 
WAF
• Broken authentication mechanism
• Privilege escalation
APPROACH 
APPROACH FOR
FORPENETRATION TESTERS
PENETRATION TESTERS(VIII)
(VIII)PHASE 6
PHASE 6
Post assessment
Objective: Inform customer about the vulnerabilities
• Advise customer to fix the root cause of a vulnerability
• For the time being, the vulnerability should be virtually 
patched by adding specific rules to the WAF
• Explain that the WAF can help to mitigate a vulnerability, 
but can not thoroughly fix it
WAFNINJA
WAFNINJA
WAFNINJA
WAFNINJA(I)
(I)OVERVIEW
OVERVIEW
• CLI Tool written in Python
• Automates parts of the approach
• Already used in several penetration tests
• Supports
• HTTPS connections
• GET and POST parameter
• Usage of cookies
WAFNINJA
WAFNINJA(II)
(II)MOST IMPORTANT FUNCTIONS
MOST IMPORTANT FUNCTIONS
Fuzz
• Reverse-engineer a WAFs rule 
set by sending different 
symbols and keywords
• Analyzes the response of every 
request
• Results are displayed in a clear 
and concise way
• Fuzzing strings can be extended 
with the insert-fuzz function
Bypass
• Brute forcing the WAF by 
enumerating payloads and 
sending them to the target
• Analyzes the response of every 
request
• Results are displayed in a clear 
and concise way
• Payloads can be extended with 
the insert-bypass function
RESULTS
RESULTS
RESULTS (I)
RESULTS (I)OVERVIEW
OVERVIEW
• Results of using WAFNinja to attempt to bypass three WAFs in a 
test environment
• Deployed WAFs used the standard configuration
• Two vulnerable web applications behind every WAF
RESULTS (II)
RESULTS (II)COMODO
COMODOWAF
WAF
• Most intelligent rule set of the three tested WAFs
• SQL Injection payload found:
• Disclosure of sensitive information:
0 union/**/select 1,version(),@@datadir
RESULTS (III)
RESULTS (III)MODSECURITY
MODSECURITYWAF
WAF
• Highly restrictive rule set
• SQL Injection payload found:
but was not processed by the back end
1+uni%0Bon+se%0Blect+1,2,3
RESULTS (IV)
RESULTS (IV)AQTRONIX
AQTRONIXWEBKNIGHT
WEBKNIGHTWAF
WAF
• Most vulnerable rule set of all three WAFs
• SQL Injection payload found:
• Disclosure of sensitive information:
0 union(select 1,@@hostname,@@datadir)
RESULTS (V)
RESULTS (V)AQTRONIX
AQTRONIXWEBKNIGHT
WEBKNIGHT
• SQL Injection payload found:
• Disclosure of personal data:
0 union(select 1,username,password from(users))
RESULTS (VI)
RESULTS (VI)AQTRONIX
AQTRONIXWEBKNIGHT
WEBKNIGHT
• XSS payload found:
• “onwheel” replaced an old JavaScript event handler
<img src=x onwheel=prompt(1)>
CONCLUSION
CONCLUSION
CONCLUSION (I)
CONCLUSION (I)
• Different Bypass Methods and Techniques have been gathered 
and categorized
• Based on these techniques a practical approach is described
• A tool which facilitates this approach was developed 
• The tool’s results contributed to finding several bypasses
CONCLUSION (II)
CONCLUSION (II)
• The given approach can improve the accuracy of penetration test 
results
• The listing of bypassing techniques can be used by vendors to 
improve their WAFs
• WAF vulnerabilities found were reported to the particular WAF 
vendors
• Ultimately: WAFs make exploiting vulnerabilities more difficult, 
but do not guarantee that a security breach will not happen
CONCLUSION (III)
CONCLUSION (III)
CONCLUSION (III)
CONCLUSION (III)
THANK YOU FOR YOUR 
THANK YOU FOR YOUR ATTENT
ATTENTION!
E-Mail: kbijjou@deloitte.de
Xing: Khalil Bijjou
