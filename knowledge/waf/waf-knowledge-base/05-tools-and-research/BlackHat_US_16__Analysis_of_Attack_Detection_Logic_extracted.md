---
id: PRESENTATIONS-BlackHat_US_16__Analysis_of_At
title: BlackHat US 16 - Analysis of Attack Detection Logic.pdf
category: Conference Presentations
severity_range: Informational
source_file: presentations/BlackHat US 16 - Analysis of Attack Detection Logic.pdf
---

# BlackHat US 16 - Analysis of Attack Detection Logic.pdf

**Category:** Conference Presentation
**File:** presentations/BlackHat US 16 - Analysis of Attack Detection Logic.pdf

## Extracted Content

Web Application Firewalls: 
Attacking detection logic 
mechanisms 
 
 
Vladimir Ivanov 
@httpsonly 
/whoam/i 
 
MSc Information Security (merit) - RHUL (UK) 
 
Web App penetration tester at Positive Technologies (ptsecurity.com) 
Agenda 
1.
Introduction 
2.
Detection logic in WAF 
3.
METHOD I: Syntax bypass 
4.
METHOD II: Logical bypass 
5.
METHOD III: Unexpected by primary logic bypass 
6.
Takeaways 
Motivation 
The Standoff: 
 
 
1. Attackers. Mix of various techniques, rarely understand root cause. 
 
2. Defenders. WAFs protect against automative testing, every vendor 
implements additional functionality. 
 
 
Result: No careful whitebox analysis 
WAF workflow example 
Stage 1: Parse HTTP(s) packet from client 
Stage 2: Chose rule set depending on type of 
incoming parameter 
Stage 3: Normalise data 
Stage 4: Apply detection logic 
 Stage 5: Make detection decision 
WAF workflow: 
Detection logic 
OWASP CRS 2 
OWASP CRS 3dev 
OWASP CRS 3rc 
PHPIDS 
Comodo rules 
QuickDefenceWaf 
Vultureproject 
Waf.red 
ShadowD 
etc… 
Tokenizer 
libinjection 
Reputation 
repsheet 
Score 
Builder 
NAXSI 
Anomaly 
detection 
HMM 
Regular expression… 
…is a sequence of characters that define a search pattern 
(?i)(<script[^>]*>.*?) 
1 
2 
3 
Sources 
500+ regular expressions: 
• OWASP CRS2 (modsecurity) 
• OWASP CRS3dev (modsecurity) 
• OWASP CRS3rc1 (modsecurity) 
• PHPIDS 
• Comodo WAF 
• QuickDefense 
43.3% 
43.8% 
12.8% 
XSS 
SQL 
Other: LFI/RFI, 
PHP, OS exec, etc 
Results 
300+ potential bypasses 
 
Most “vulnerable”: PHPIDS (E = 1,15) 
Less “vulnerable”: Comodo WAF (E = 0,32) 
Most “exploitable”: OWASP CRS3-rc (E = 0,89) 
 
 
 
E = Potential bypasses / Total rules 
METHOD I: Syntax bypass 
Of regular expressions 
 
 
Enumerate all possible and invent all impossible mistakes 
What’s wrong with regexp? 
Level: Easy 
! 
What’s wrong with regexp? 
Level: Easy 
(?i:     ) 
1.   atTacKpAyloAd  
! 
What’s wrong with regexp? 
Level: Easy 
(?i:     ) 
^        $ 
1.   atTacKpAyloAd  
2.                 attackpayload 
! 
What’s wrong with regexp? 
Level: Easy 
(?i:     ) 
^        $ 
{1,3} 
1.   atTacKpAyloAd  
2.                 attackpayload 
3.   attackpayloadattackpayloadattackpayloadattackpa… 
! 
What’s wrong with regexp? 
Level: Medium 
ReDoS 
1.  
What’s wrong with regexp? 
Level: Medium 
ReDoS 
Repetitions:   +  * 
1.  
2.  
What’s wrong with regexp? 
Level: Medium 
ReDoS 
Repetitions:   +  * 
Blacklisting wildcards in a set 
1.  
2.  
3.  
What’s wrong with regexp? 
Level: Advanced 
Non-standard diapasons 
1.  
POSIX character classes 
2.  
Operators 
3.  
Backlinks, wildcards 
4.  
Regular expressions: 
Security cheatsheet 
2 parts: theoretical "whitepaper" and practical "code". 
Hack regular expressions with regular expressions!  
 
+  SAST: Assists with whitebox analysis of regular expressions in source 
code of your projects 
+  Low false positives: Focused on finding high severity security issues 
+  Opensource on Github! 
-   Does not dynamically analyze lexis (yet). 
 
https://github.com/attackercan/ 
REGEXP-SECURITY-CHEATSHEET 
Target audience 
Not only WAFs use Reg Exp Detection Logic: 
 
• XSS Auditors 
• Backend parsers 
• Front-end analyzers 
 
Developers, security auditors, bughunters 
DEMO 
 
 
Regex Security Cheatsheet DEMO 
^(?:ht|f)tps?://(.*)$ 
Comodo WAF: 
Att4ck is bl0cked! 
(\bunion[\s\\*\/]{1,100}?\bselect\b) 
QuickDefense WAF: 
Attackers are lazy enough 
JavaScript checker in real-life web app 
JavaScript checker in real-life web app 
We can make ReDoS on client-side by supplying specially crafted email as input. 
JavaScript checker in real-life web app 
We can make ReDoS on client-side by supplying specially crafted email as input. 
But what if backend also has same regex for checking? 
JavaScript checker in real-life web app 
We can make ReDoS on client-side by supplying specially crafted email as input. 
But what if backend also has same regex for checking? 
EdgeHTML.dll 
EdgeHTML.dll 
IE+Edge XSS 
Auditor 
EdgeHTML.dll 
IE+Edge XSS 
Auditor 
Result: 
blocked 
EdgeHTML.dll 
Regexp 
bypass. 
Result: alert! 
Thx @ahack_ru for payload 
(?:div|like|between|and|not )\s+\w) 
(?:div|like|between|and|not )\s+\w) 
https://github.com/PHPIDS/PHPIDS/commit/667e63af93e8fd2ee4df99dd98cb41acdf480906 
What’s next? 
1. Identify WAF vendor and version using “signature” vulnerabilities. 
What’s next? 
1. Identify WAF vendor and version using “signature” vulnerabilities. 
2. Reveal and apply bypasses depending on a situation 
What’s next? 
1. Identify WAF vendor and version using “signature” vulnerabilities. 
2. Reveal and apply bypasses depending on a situation 
3. Craft string which bypasses all regexp-based rules. 
ModSecurity SQLi Bypass 
Basic SQLi is given: 
 
 
 
All SQLi Regexp bypass: 
 
​-1'OR#foo 
id=IF#foo 
(ASCII#foo 
((SELECT-version()/1.))<250,1,0) # 
 
What’s next? 
1. Identify WAF vendor and version using “signature” vulnerabilities. 
2. Reveal and apply bypasses depending on a situation 
3. Craft string which bypasses all regexp-based rules. 
4. … 
What’s next? 
1. Identify WAF vendor and version using “signature” vulnerabilities. 
2. Reveal and apply bypasses depending on a situation 
3. Craft string which bypasses all regexp-based rules. 
4. … 
5. Dig deeper! 
METHOD II: Logical bypass 
Manual review analysis 
 
 
+Non-standard findings 
- Subjective 
Blacklists fail #1 
https://github.com/netty/netty/issues/5535 
Blacklists fail #2, 3, 4, … 
NAXSI 
0x 
0b10101 
b’10101’ 
ModSecurity 2.2.9 
XSS Rule 973300 
<(a|abbr|acronym|... 
<non_existing_tag 
onmouseover=alert(1)>hover this! 
ModSecurity 3RC-1 
OS-Commands.data 
adduser 
useradd 
ipconfig 
ifconfig 
copy, move 
cp, mv 
Researches success 
@mazen160 
Researches success 
@mazen160 
METHOD III: Unexpected 
by primary logic bypass 
XSS Fuzzer 
XSS Fuzzer 
libinjection 
libinjection 
https://github.com/attackercan/ 
CPP-SQL-FUZZER 
•  Receive SQL query as input 
•  Fuzz it (mysql.h, SQLAPI.h, ODBC?) 
•  Record every query except syntax errors 
•  Parse output! 
 
 
•  Current MySQL.h perfomance: 21M symbols in <1 hour; 
    speed = 9k queries per second (QPS). 
•  Up to 1.6M QPS! 
SQL fuzzer 
SQL fuzzer: Examples 
SQL Fuzzer: Results 
Contribution 
• Regexp security cheatsheet + SAST 
• Blacklist improvement 
• SQL Fuzzer: Classified tables 
 
https://github.com/attackercan 
TODO 
1.
Update Regular Expression Security Cheatsheet 
 
2.
Create regular expression Dynamic analysis tool 
 
3.
“Clever fuzzing” + scalable (MySQL allows 1.6M QPS) 
 
Questions? 
Thank you 
Arseniy Sharoglazov   <mohemiv@gmail.com> 
(Contribution to Regex Security Cheatsheet) 
 
Dmitry Serebryannikov    @dsrbr 
(Contribution to SQL fuzzer) 
 
Andrey Evlanin    @xpathmaster 
 
All @ptsecurity team ;)
