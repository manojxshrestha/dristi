---
id: PRESENTATIONS-Building_Your_Own_WAF_as_a_Ser
title: Building Your Own WAF as a Service and Forgetting about False Positives.pdf
category: Conference Presentations
severity_range: Informational
source_file: presentations/Building Your Own WAF as a Service and Forgetting about False Positives.pdf
---

# Building Your Own WAF as a Service and Forgetting about False Positives.pdf

**Category:** Conference Presentation
**File:** presentations/Building Your Own WAF as a Service and Forgetting about False Positives.pdf

## Extracted Content

Building Your Own WAF as a 
Service and Forgetting about False 
Positives
1
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Juan Berner
@89berner
Lead security developer 
@Booking.com
2
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Blog: medium.com/@89berner
Overview
●Introduction to WAF & deployment modes
●WAF as a service
●Blocking attacks without false positives or 
increased latency
●Demo
3
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
WAF?
●Web Application Firewall
●Mainly used to protect against Application Attacks
●SQLi, RCE, Protocol Violations, Rate Limiting ...
4
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Deployment mode - Inline
●Pros:
○
Traffic inspection
○
Ability to block
○
Transparent for web servers
●
Cons:
○
Network placement
○
Latency
5
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Deployment mode - Out of band
●Pros:
○
Traffic inspection
○
Transparent for web servers
○
Simpler network placement
●
Cons:
○
Can’t block attacks
○
PFS
6
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Deployment mode - Agent
●Pros:
○
Easier network placement
○
Simple to scale
●
Cons:
○
More invasive on deployment environment
○
Can be less efficient on resource allocation
7
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Deployment mode - Cloud
●Pros:
○
Simple to setup and scale
○
Network effect
●
Cons:
○
Out of your control
○
Latency added
8
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Caveats with typical WAF Solutions
●Network placement
●Availability and performance concerns
●False positive rate
●Lack of control from developers
9
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Building the WAF as a Service
●Removes FP by having an understanding of the 
application context
●No need for an appliance, just add an API call
●Blocking behaviour is decided by the application
●Ability to avoid latency for regular users
10
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
How could you build one? 
●Open source components already exist
●Creating a log processing pipeline
●Building a WAF API
●Library for logs and calling API
11
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Case study: Web application  
●Setup in Google Cloud
●Flask microframework
●Code available in github
12
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Finding a middle ground
●Out of band mode removes concerns of latency 
added to users
●Inline mode provides security by blocking attacks
●Could we get the best of both worlds?
13
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Web application
14
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Web application
●Can decide which mode to work on
○Inline
○Out of band
●Sends logs with partial request data encrypted
Example: Flask
15
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Agent
●Acts as a reverse proxy
●Minimal footprint
●Application agnostic
●Can get settings from the application
16
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Library
●Simple to implement
●Inherent risks
●Strategy for this talk
17
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - WAF service
18
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - WAF service
●Pluggable architecture
●Parallel nature of their components
●Applications can decide how to react
19
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - WAF service
●Open source components
○Modsecurity
○Naxsi
20
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - WAF service
●Proprietary software or appliances
○Reduced complexity of installation
○Simple way of evaluation
21
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - WAF service
●Custom modules
○Apply custom business logic
○Implement simple services
■Rate limiting
■Rule engine for blocking
○ML models
22
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
WAF service
23
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Log processing
24
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Log processing
●Replays logs that were not in line against WAF
●Calculates scores through windows of time
25
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Google 
Dataflow
Components - Detection
26
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Detection
●Triggered by Log Processing
●Business value
●Patterns of behaviour for FP
27
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - State store
28
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - State store
●Allows to store configuration
●Ideally fast lookup for caching
29
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Visualisation
30
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Visualisation
●Easily understand activity
●Visibility on attacks
●Performance metrics
Example: ELK
31
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Visualisation
32
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Visualisation
33
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Components - Management
34
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
How to block?
●Detection decides when to send traffic to the WAF
●Can also be triggered manually
35
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Traffic routing
●Fingerprint based routing
○Blocks based on scores
○IP, client_id, combinations, 0day signatures ..
○Added automatically or manually
36
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Traffic routing
●Net block based routing
○ISP
○Hosting providers
○Tor exit nodes / Proxies
37
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Traffic routing
●Virtual Patching
○Always route particular vulnerable endpoints
○Select for combination of parameters if needed
○Example: website.com/?vuln_param=
38
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
FP rate management
●Detection FP vs blocking FP
●Key to allow blocking without impacting users
●Acceptable rate might change per application
●Tuning can become unbearable in highly changing 
applications
39
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
FP rate management
●Business logic
○How trustworthy is a user/ip?
○Key business activity
○What would be the impact on blocking them
40
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
FP rate management
●Historical Analysis
○How normal is this type of request for this 
endpoint?
○How does this user compare with others
○How common are detection FP in this endpoint
41
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
FP rate management
●Context analysis
○How many times have they triggered a FP
○How many requests have they sent
42
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
FP rate management
●Example: Sleep(
○message=“I will sleep(1 or 2 days)”
■Might be detected as SQLI
■Probability of FP is independent from each 
other
43
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
FP rate management
●Independant SQLI FP rate: 0.1%
●Our aim, 0.00001% (0.01^5)
●Score needed => 5 * Reputation Score 
●Aimed at attacks that need volume
44
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Hybrid mode
●Benefits
○WAF does not add latency for good users
○Flexibility
○Removes FP’s
45
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Hybrid mode
●Caveats
○Delayed response time for blocking 
when using identifier mode
○Increased complexity
46
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
47
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Request lifetime - Initial request
48
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
1
Request lifetime - Cache check
49
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
2
Request lifetime - Request encapsulation
50
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
3
Request lifetime - Out of band processing
51
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
4
Request lifetime - Attack detection
52
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
5
Request lifetime - Additional requests
53
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
6
Request lifetime - Cache update
54
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
7
Request lifetime - Inline behaviour
55
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
8
Summary (1/2)
●
Reduced customer impact
○
Use hybrid mode to only add latency to malicious actors
○
Stops false positives from affecting customers through 
understanding history, context and business metrics
○
Specify different behaviour based on endpoint’s risk
56
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
Summary (2/2)
●
Flexibility
○
Extensible through third party products or custom 
plugins
○
Allows developers to integrate through api calls where 
needed
57
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
What now?
●Try it!
●https://github.com/89berner/waf-api-talk
●git clone https://github.com/89berner/waf-api-talk 
&& cd waf-api-talk; ./setup $YOUR_GCP_PROJECT
●Questions?
58
Building Your Own WAF as a Service and Forgetting about False Positives
Juan Berner
