---
layout: post
title: "Essential Websites Every Hacker Should Know"
date: 2025-08-19 23:30:00 +0000
categories: [Pentesting, Resources]
tags: [tools, osint, malware, recon, security]
---

# Essential Websites Every Hacker Should Know

A curated list of websites every hacker, pentester, or security enthusiast should know. Organized by category with short descriptions and suggested usage.

---

## 🕵️ OSINT & Recon
- [OSINT Framework](https://osintframework.com/) – Collection of OSINT tools organized by category. *Use for: emails, domains, social profiles, metadata.*  
- [Shodan](https://www.shodan.io/) – Search engine for internet-connected devices. *Use for: finding exposed devices/services.*  
- [Censys](https://search.censys.io/) – Search engine for certificates and hosts. *Use for: discovering vulnerable infrastructure.*  
- [Grep.app](https://grep.app/) – Search across millions of open-source code repositories quickly.  
- [Have I Been Pwned](https://haveibeenpwned.com/) – Breach data lookup. *Use for: checking email/domain compromises.*  
- [Hunter.io](https://hunter.io/) – Email discovery. *Use for: recon on valid emails.*  
- [crt.sh](https://crt.sh/) – SSL certificate transparency logs. *Use for: finding subdomains.*  
- [DNSDumpster](https://dnsdumpster.com/) – DNS mapping. *Use for: subdomains, MX records, IP ranges.*  
- [Social Searcher](https://www.social-searcher.com/) – Search mentions across social media. *Use for: usernames, activity tracking.*  
- [Web Archive / Wayback Machine](https://web.archive.org/) – Archived website versions. *Use for: old endpoints, leaks.*  
- [LeakIX](https://leakix.net/) – Exposed servers/devices. *Use for: discovering leaks.*  
- [FOFA](https://en.fofa.info/) – Internet asset search. *Use for: ports, devices, services.*  
- [TruePeopleSearch](https://www.truepeoplesearch.com/) – People search engine. *Use for: public personal info.*  
- [FastPeopleSearch](https://www.fastpeoplesearch.com/) – Alternative people lookup. *Use for: addresses, phone numbers.*  
- [GreyNoise](https://viz.greynoise.io/) – Noise analysis. *Use for: filtering harmless vs malicious IPs.*  
- [Netlas Host Search](https://app.netlas.io/host/) – Network asset search. *Use for: IP/domain recon.*  
- [TinEye](https://tineye.com/) – Reverse image search. *Use for: image origins.*  
- [PimEyes](https://pimeyes.com/en) – Facial recognition search. *Use for: person image lookup.*  
- [Redirect Checker](https://www.redirect-checker.org/) – Trace URL redirects. *Use for: identifying hidden jumps in redirects.*  
- [WhereGoes](https://wheregoes.com/) – Visualize redirect chains. *Use for: seeing full URL redirection flow.*  
- [HTTP Status Checker](https://httpstatus.io/) – Inspect HTTP codes and headers. *Use for: debugging web requests and redirects.*  
- [Unshorten.It](https://unshorten.it/) – Expand shortened URLs. *Use for: revealing hidden destinations.*  
- [BGPView](https://bgpview.io/) – BGP and ASN lookup. *Use for: investigating network ranges.*  
- [Hurricane Electric BGP](https://bgp.he.net/) – BGP routing and prefix search. *Use for: network-level recon.*  
- [IPVoid](https://www.ipvoid.com/) – IP reputation checker. *Use for: analyzing IPs for blacklists or malicious history.*  
- [AbuseIPDB](https://www.abuseipdb.com/) – IP abuse reporting database. *Use for: checking if an IP is reported for attacks.*  
- [NSLookup.io](https://www.nslookup.io/) – DNS record lookup. *Use for: inspecting DNS configuration.*

---

## ☣️ Malware & Threat Analysis
- [VirusTotal](https://www.virustotal.com/gui/home/url) – Scan files, URLs, and domains. *Use for: malware detection.*  
- [Hybrid Analysis](https://hybrid-analysis.com/) – Online malware sandbox. *Use for: suspicious file analysis.*  
- [Any.run](https://any.run/) – Interactive malware analysis. *Use for: live malware behavior tracking.*  
- [MalwareBazaar](https://bazaar.abuse.ch/) – Malware samples repo. *Use for: researching malware families.*  
- [CyberChef](https://gchq.github.io/CyberChef/) – Data analysis toolkit. *Use for: encode/decode, hash, manipulate data.*  
- [URLScan](https://urlscan.io/) – URL isolation & scanning. *Use for: phishing/malware site detection.*  
- [BrowserLeaks](https://browserleaks.com/) – Test browser leaks/fingerprints. *Use for: privacy & recon.*  
- [Sucuri SiteCheck](https://sitecheck.sucuri.net/) – Website scanner. *Use for: infections, vulnerabilities.*  
- [Web-Check.xyz](https://web-check.xyz/) – Website reputation check. *Use for: security overview.*  

---

## 🔑 Passwords & Hashes
- [CrackStation](https://crackstation.net/) – Password hash cracking. *Use for: recovering plain-text passwords.*  
- [MD5Decrypt](https://md5decrypt.net/en/) – Hash decryption. *Use for: MD5, SHA1 lookups.*  
- [Hashes.com](https://hashes.com/en/decrypt/hash) – Online hash cracking. *Use for: multiple hash types.*  

---

## 💣 Vulnerability & Exploit Research
- [Exploit-DB](https://www.exploit-db.com/) – Exploit database. *Use for: public PoCs.*  
- [CVE Details](https://www.cvedetails.com/) – CVE database. *Use for: software/vendor vulnerabilities.*  
- [NVD](https://nvd.nist.gov/) – Official CVE database. *Use for: CVE lookups, scoring.*  
- [Packet Storm Security](https://packetstormsecurity.com/) – Exploits, advisories, tools. *Use for: PoCs & security research.*  
- [Pentest Tools Website Scanner](https://pentest-tools.com/website-vulnerability-scanning/website-scanner) – Web vuln scanner. *Use for: quick online scans.*  

---

## 🌐 Recon & Infrastructure Info
- [IPinfo](https://ipinfo.io/) – IP & ASN lookup. *Use for: mapping network infrastructure.*  
- [ZoomEye](https://www.zoomeye.ai/) – IoT/device search engine. *Use for: exposed services.*  
- [JWT Auditor](https://jwtauditor.com/) – JWT inspection. *Use for: token misconfig checks.*  
- [JWT Lens](https://jwtlens.netlify.app/) – JWT analyzer. *Use for: quick token decoding.*  

---

## ⚔️ Reverse Shells & Exploitation
- [Reverse Shells](https://www.revshells.com/) – Reverse shell generator. *Use for: payload creation.*  
- [GTFOBins](https://gtfobins.github.io/) – Unix privilege escalation tricks. *Use for: post-exploitation.*  
- [LOLBAS](https://lolbas-project.github.io/) – Windows binaries abuse. *Use for: Windows privilege escalation.*  
- [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration) – Linux enum script. *Use for: privilege escalation recon.*  
- [PEASS-ng](https://github.com/peass-ng/PEASS-ng) – Privilege escalation tools. *Use for: Linux/Windows post-exploitation.*  

---

## 🎭 Phishing & Privacy
- [PhishTank](https://www.phishtank.com/) – Phishing database. *Use for: URL phishing checks.*  
- [Boostfluence Instagram Viewer](https://www.boostfluence.com/free-tools/instagram-profile-viewer) – Anonymous Instagram viewing. *Use for: social OSINT.*  
- [Temp-Mail](https://temp-mail.org/) – Disposable emails. *Use for: anon registrations.*  
- [SMS24](https://sms24.me/en) – Temporary phone numbers. *Use for: SMS verification bypass.*  

---

## 📚 Hacking & Security References
- [HackTricks](https://book.hacktricks.xyz/) – Hacking techniques & cheatsheets. *Use for: pentest guidance.*  
- [Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking) – Massive collection of hacking tools and resources.  
- [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty) – Curated list of bug bounty resources.  
- [TBHM](https://github.com/jhaddix/tbhm) – The Bug Hunter’s Methodology (Jason Haddix).
- [Awesome Red Team Cheatsheet](https://github.com/RistBS/Awesome-RedTeam-Cheatsheet) – A massive collection of red team tactics, tools, and references.  
- [Ghostpack Compiled Binaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) – Precompiled Ghostpack binaries useful for red team operations.  
- [HackerTyper](https://hackertyper.net/#) – Fun website to “look like” you’re coding like a hacker.  
- [Hacker News](https://news.ycombinator.com/news) – Daily tech, security, and startup news.  
- [The Hacker Recipes](https://www.thehacker.recipes/) – A comprehensive knowledge base of offensive security techniques, tactics, and playbooks.
- [Exploit Database](https://www.exploit-db.com) – Public exploits & proof-of-concepts.  
- [Packet Storm](https://packetstormsecurity.com) – Exploits, advisories, and security tools.  
- [0day.today](https://0day.today) – Exploit and vulnerability database.  
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) – Attack payloads collection. *Use for: XSS, SQLi, LFI, RCE.*  
- [Bug Bounty Cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet) – Bug bounty methodology. *Use for: hunting workflow.*  
- [IntelX](https://intelx.io/) – Leak search engine. *Use for: leaked docs, emails, creds.*  
- [Notes by Ben Heater](https://notes.benheater.com/) – Security notes repo. *Use for: learning material.*  
- [Patorjk.com](https://patorjk.com/) – Text & ASCII utilities. *Use for: ASCII art, text manipulation.*  

---

## 🛰️ Threat Modeling & Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/) – Knowledge base of adversary TTPs. *Use for: detection, attack mapping.*  

---

## 📂 OSINT GitHub Repositories
- [Telegram OSINT](https://github.com/cqcore/Telegram-OSINT)  
- [Data Acquisition OSINT](https://github.com/The-Osint-Toolbox/Data-OSINT)  
- [Social Media OSINT](https://github.com/The-Osint-Toolbox/Social-Media-OSINT)  
- [Website OSINT](https://github.com/The-Osint-Toolbox/Website-OSINT)  
- [People OSINT](https://github.com/The-Osint-Toolbox/People-Search-OSINT)  
- [Geo-Location OSINT](https://github.com/The-Osint-Toolbox/Geolocation-OSINT)  
- [Image OSINT](https://github.com/The-Osint-Toolbox/Image-Research-OSINT)  
- [Email Username OSINT](https://github.com/The-Osint-Toolbox/Email-Username-OSINT)  
- [YouTube Video OSINT](https://github.com/The-Osint-Toolbox/YouTube-Video-OSINT)  
- [GitHub OSINT Resources](https://github.com/The-Osint-Toolbox/GitHub-OSINT-Resources)  
- [OSINT Peripherals](https://github.com/The-Osint-Toolbox/OSINT-Toolbox-Peripherals)  
- [OSINT Practitioners](https://github.com/The-Osint-Toolbox/OSINT-Practitioners)  

### 🔍 Search Tools & Techniques
- [Advanced Searching OSINT](https://github.com/The-Osint-Toolbox/OSINT-Advanced-Searching)  
- [Custom Search Engines](https://github.com/The-Osint-Toolbox/Custom-Search-Engines)  
- [URL-Manipulation OSINT](https://github.com/The-Osint-Toolbox/URL-Manipulation)  
- [Fact Checking OSINT](https://github.com/The-Osint-Toolbox/Fact-Checking-Verification)  

### 🎯 Specific OSINT Areas
- [Darkweb OSINT](https://github.com/The-Osint-Toolbox/Darkweb-OSINT)  
- [WiFi OSINT](https://github.com/The-Osint-Toolbox/WiFi-OSINT)  
- [Vehicle OSINT](https://github.com/The-Osint-Toolbox/Vehicle-OSINT)  
- [Telephone OSINT](https://github.com/The-Osint-Toolbox/Telephone-OSINT)  
- [Fitness OSINT](https://github.com/The-Osint-Toolbox/Fitness-Leisure-OSINT)  

### 🛡️ Privacy & OPSEC
- [Privacy Infosec Tools](https://github.com/The-Osint-Toolbox/Privacy-Infosec-Tools-Resources)  
- [VPN Providers OSINT](https://github.com/The-Osint-Toolbox/VPN-Providers)  
- [Privacy Opt-Out OSINT](https://github.com/The-Osint-Toolbox/Privacy-Opt-Out)  

---

## 🌑 Dark Web Resources ⚠️
⚠️ **Warning:** Requires Tor Browser. Use only for legal OSINT & research.  

- [The Hidden Wiki](https://thehiddenwiki.org/)  
- [Onion Wiki Mirror](http://zqktlwi4fecvo6ri.onion/wiki/index.php/Main_Page)  
- [Onion Links Archive](http://donionsixbjtiohce24abfgsffo2l4tk26qx464zylumgejukfq2vead.onion/onions.php)  
- [ProPublica Onion](https://www.propub3r6espa33w.onion)  
- [Sci-Hub Onion](http://scihub22266oqcxt.onion/)  
- [Dark Web Q&A](http://answerszuvs3gg2l64e6hmnryudl5zgrmwm3vh65hzszdghblddvfiqd.onion/)  
- [Library Genesis Onion](http://ulrn6sryqaifefld.onion/)  
- [Facebook Onion](https://www.facebookcorewwwi.onion/)  
- [Archive.org Onion](http://archivecaslytosk.onion/)  
- [CIA Onion](http://ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion/)  

---

💡 **Tip:** Bookmark and organize these resources by category. Always use them ethically in **labs, CTFs, or authorized pentests** only.

