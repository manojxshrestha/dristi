---
id: PRESENTATIONS-Side_Channel_Attacks_for_Finge
title: Side Channel Attacks for Fingerprinting WAF Filter Rules.pdf
category: Conference Presentations
severity_range: Informational
source_file: presentations/Side Channel Attacks for Fingerprinting WAF Filter Rules.pdf
---

# Side Channel Attacks for Fingerprinting WAF Filter Rules.pdf

**Category:** Conference Presentation
**File:** presentations/Side Channel Attacks for Fingerprinting WAF Filter Rules.pdf

## Extracted Content

WAFFle:
Fingerprinting Filter Rules of
Web Application Firewalls
Isabell Schmitt, Sebastian Schinzel*
Friedrich-Alexander Universität Erlangen-Nürnberg
Lehrstuhl für Informatik 1
IT-Sicherheitsinfrastrukturen
Email: sebastian.schinzel@cs.fau.de
Twitter: @seecurity
*supported by Deutsche Forschungsgemeinschaft (DFG) as part of SPP 1496 “Reliably Secure Software Systems”
Introduction: Web Application Firewalls
2
Demilitarized 
Zone
Intranet
Blocked Request
Passed Request
Internet
Web Server
Web Application Firewalls
✴intercept web requests
✴ﬁlter requests to prevent 
attacks
✴uses ﬁlter rules for detecting 
common attack patterns
✴blind for “new” attack patterns
✴If attacker knows active ﬁlter rule set, he can search for loopholes in the rule set
✴What can the attacker learn about the active ﬁlter rule set of a WAF?
Introduction: Related Work
3
How can the attacker learn active ﬁlter rule set? 
✴WAFW00f detects if a web page is protected by a WAF and can differentiate between 
22 different WAF producers (no active rule set)
✴analyses HTTP status codes, cookies, etc.
✴WAF Tester ﬁngerprints WAF ﬁlter rules by analyzing the HTTP status codes and 
whether the WAF drops or rejects the HTTP request on the TCP layer
✴analyses error conditions 
✴no visible error condition == no ﬁngerprinting possible
Visibility of Web Application Firewalls
4
1.  Response shows WAF error message
a) the rogue request was blocked by the WAF or
b) the WAF passed the request to the web application that responded with an error message and which was then 
cloaked by the WAF
2.  Response shows Webapp error message
a) WAF neither blocked the request, nor cloaked the web application’s error message
3.  Response shows Normal response
a) WAF removed the malicious part of the rogue request
b) WAF passed the rogue request but webapp ignored the malicious part of the request
c) WAF passed the rogue request and the malicious part was executed, but it produced no visible result
Introduction to Timing Side Channel Attacks
5
T
Attacker (client)
Server
pass
correct?
true
login(user, pass)
t0
true
false
“An error occured”
t1
false
“An error occured”
t2
  ⇒ user does not exist
⌛
⌛
  ⇒ user exists
Other examples for 
side channels:
✴sound
✴visuals
✴emissions
✴power consumption
✴motion (mobiles)
✴size of encrypted 
packages
user
correct? 
1. Scenario: mod_security as Reverse Proxy
6
Demilitarized 
Zone
Intranet
Blocked Request
Passed Request
Internet
Web Server
mod_security ﬁltering on 
reverse proxy
✴Request gets passed to Web 
server iff request is not 
blocked by ﬁlter set
✴Blocked requests are never 
passed to Web server
2. Scenario: mod_proxy as Web Server Plugin
7
Demilitarized 
Zone
Intranet
Internet
Web Server
mod_security ﬁltering as 
web server plugin
✴Request gets passed to Web 
application iff request is not 
blocked by ﬁlter set
✴Blocked requests are never 
passed to Web application
3. Scenario: PHPIDS as Programming Library
8
mod_security ﬁltering as 
web application plugin
✴Request gets passed to 
business logic iff request is not 
blocked by ﬁlter set
✴Blocked requests are never 
passed to business application
Demilitarized 
Zone
Intranet
Internet
Web Server
WAFﬂe: Fingerprinting Filter Rules of Web Application Firewalls
9























Idea behind WAFﬂe
1. Generate polymorphic 
representations of exploit code 
(e.g. 
<script>alert(23);</script>,
<script_>alert(23);</script>,
<script__>alert(23);</script>
<script___>alert(23);</script>)
2. Send to web app and measure 
response time
3. Analyse response time
Demilitarized 
Zone
Intranet
Blocked Request
Passed Request
Internet
Web Server
WAFﬂe: Fingerprinting Filter Rules of Web Application Firewalls
10
Two phases of WAFle
1. Learning phase
a) measure response times T 
of n passed requests
b) deﬁne “blocking boundary” 
as b = min(T ) - ɛ
2. Attack phase
a) send probe and measure t
b) blocked request if t < b
+
+
+
+
+
+
+
+
+
+
+
+
+
+
Passed requests
X
Blocked request
X
No decision possible:
a) passed request + low jitter
OR
b) blocked request + high jitter
#
1. Learning phase
2. Attack phase
Blocking boundary
Response time
WAFﬂe: Fingerprinting Filter Rules of Web Application Firewalls
11























WAFﬂe: Results
12
Demilitarized 
Zone
Intranet
Blocked Request
Passed Request
Internet
Web Server
mod_security ﬁltering on reverse 
proxy
WAFﬂe: Results
13
Demilitarized 
Zone
Intranet
Internet
Web Server
mod_security ﬁltering as web 
server plugin
WAFﬂe: Results
14
Demilitarized 
Zone
Intranet
Internet
Web Server
mod_security ﬁltering as web 
application plugin
WAFﬂe: Results
15
Results
✴All three scenarios allow to 
distinguish blocked from passed 
requests by observing response times
✴With no repetitions, >95% of single 
requests already correctly determine 
blocked and passed requests
1(a)
1(b)
1(c)
WAFﬂe: Cross Site Timing Attack
16
One more thing...
✴We’re on the web, and the web allows cross site requests
✴Extend WAFﬂe for Cross Site Request Forgery (Cross Site Timing Attack)
Victim Web Application
Web User
Attacker
3)
2)
 4) Sends Measurements
Web Browser
Web Site
 1) Visits
WAF
✴Generate Javascript code that 
attacker embeds on web page
✴Attacker tricks other users to visit 
web page
✴other users perform measurement 
and send measurements to attacker
Cross-Site Timing Attack
17
WAFﬂe: Cross Site Timing Attack
18
Cross Site Timing Attack
Summary
19
✴Introduced a new timing attack against WAFs that directly distinguishes passed 
requests from blocked requests without relying on ambiguous error messages
✴Tested the attack over an Internet connection against three common WAF 
deployment setups and showed that the attack is highly practical
✴Combined our timing attack with XSRF,
✴hides the attacker’s identity
✴prevents the WAF from blocking the attack (assuming that the attacker 
distributes the attack to many other users)
20
Thanks!
Discussion.
Email: sebastian.schinzel@cs.fau.de
Twitter: @seecurity
