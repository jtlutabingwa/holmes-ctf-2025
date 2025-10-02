# Holmes CTF 2025: *The Tunnel without Walls*
**Author:** Jonathan Lutabingwa ([@jtlutabingwa](https://github.com/jlutabin))

**Team:** Sherlock's Homies
- [Jonathan Lutabingwa](https://www.linkedin.com/in/jonathan-lutabingwa/)  
- [Benjamin Taylor](https://www.linkedin.com/in/btayl106/)  
- [Greyson Brummer](https://www.linkedin.com/in/greyson-brummer-b82119301/)  
- [Lansina Diakite](https://www.linkedin.com/in/lansina-diakite-7a673b202/)  
- [Shaunak Peri](https://www.linkedin.com/in/shaunak-peri-315744245/)

---

**Table of Contents**:
- 🟩 ["The Card"](./holmes_the_card.md)
- 🟨 ["The Watchman's Residue"](./holmes_watchmans_residue.md)
- 🟩 ["The Enduring Echo"](./holmes_enduring_echo.md)
- 🟥 ["The Tunnel Without Walls"](./holmes_tunnel_without_walls.md)
- 🟥 ["The Payload"](./holmes_the_payload.md)
  
---

## 📋 TL;DR (Answers)

- **Linux kernel version:** `5.10.0-35-amd64`
- **Attacker shell PID:** `13608`
- **Escalated credentials (user:password):** `jm:WATSON0`
- **Malicious file full path:** `/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko`
- **Author email:** `i-am-the@network.now`
- **Package name and PID:** `dnsmasq,38687`
- **Compromised workstation hostname:** `Parallax-5-WS-3`
- **Portal username:** `mike.sullivan`
- **Update endpoint:** `/win10/update/CogSoftware/AetherDesk-v74-77.exe`
- **Original domain, final redirect:** `updates.cogwork-1.net,13.62.49.86:7477`

---

**Prompt:** A memory dump from a connected Linux machine reveals covert network connections, fake services, and unusual redirects. Holmes investigates further to uncover how the attacker is manipulating the entire network!

**Summary:** Memory analysis revealed an attacker establishing an SSH foothold, running reconnaissance, escalating via stolen credentials, installing a rootkit from Pastebin, reconfiguring network services, and redirecting software updates to deliver a supply-chain attack.

**🟥 Challenge Difficulty:** *HARD*

---

# Flags & Walkthrough
 
---

## 🚩 Flag 1 — Kernel Version  
**Question:** What is the Linux kernel version of the provided image?  
**Context:** Identify kernel so correct Volatility profile/symbols can be used.  
**Explanation:**  
I loaded `memdump.mem` into Volatility3 and ran the `linux.banners` (or `linux.banners`-equivalent) plugin to extract OS/banner strings that the kernel left in memory. Those banner strings commonly include the full kernel release; in this case the banner returned the Debian-style release string. Knowing the exact kernel allows you to select the correct symbol files and avoid false negatives in subsequent memory analysis.  
**Answer:** `5.10.0-35-amd64`

---

## 🚩 Flag 2 — Attacker Shell PID  
**Question:** The attacker connected over SSH and executed initial reconnaissance commands. What is the PID of the shell they used?  
**Context:** Find the interactive shell spawned by the remote SSH session.  
**Explanation:**  
With the correct profile loaded, I enumerated the process tree (`linux.pstree`) to follow the `sshd` session children. `sshd` forks per session; following the child chain (sshd → sshd → bash) revealed a `bash` process running under an sshd' child. The `bash` process PID that corresponds to the remote interactive session and to the timing of the reconnaissance commands is `13608`. Confirming parent-child relationships ensures we picked the remote shell rather than a local shell.  
**Answer:** `13608`

---

## 🚩 Flag 3 — Escalated Credentials  
**Question:** After the initial information gathering, the attacker authenticated as a different user to escalate privileges. Submit that user's credentials.  
**Context:** Attacker used `su` to switch user; recover password from memory.  
**Explanation:**  
Bash history and `linux.bash` output showed the attacker ran `su jm`. I scanned memory for passwd/shadow-like entries and found the `jm` account line containing an MD5-crypt hash (`$1$jm$...`). Exporting that hash and cracking it with Hashcat (MD5-crypt mode) produced the cleartext `WATSON0`. Combining the username from the `su` command and the cracked password gives the credential pair `jm:WATSON0`. This method ties a command in history to a concrete authentication artifact recovered from memory.  
**Answer:** `jm:WATSON0`

---

## 🚩 Flag 4 — Malicious File Path  
**Question:** The attacker downloaded and executed code from Pastebin to install a rootkit. What is the full path of the malicious file?  
**Context:** Locate the installed kernel module (rootkit .ko file path).  
**Explanation:**  
I used `linux.malware.check_modules` (module listing) to surface suspicious kernel modules found in memory. The module name `Nullincrevenge` was flagged. To map that module to an on-disk/in-memory file, I inspected pagecache entries (`linux.pagecache.Files` / `linux.pagecache.inodePages`), which list cached file paths referenced in RAM. That mapping pointed to the module file path shown below. Recovering the file path lets you extract the module binary for offline analysis.  
**Answer:** `/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko`

---

## 🚩 Flag 5 — Author Email  
**Question:** What is the email account of the alleged author of the malicious file?  
**Context:** Extract embedded metadata from the module.  
**Explanation:**  
After dumping the module pages from the page cache, I ran `strings` over the extracted buffer to look for human-readable metadata. The module contained an author/contact string embedded in its data. That embedded email address is the author/contact artifact recovered directly from the module image in memory.  
**Answer:** `i-am-the@network.now`

---

## 🚩 Flag 6 — Package Name and PID  
**Question:** The attacker installed a network service package. What is the package name and PID?  
**Context:** Identify the installed service and its running PID in memory.  
**Explanation:**  
Bash history shows the attacker used package management commands to install a network service. The command stream references `dnsmasq`. I then looked at the process list snapshot (from the pstree or ps-like plugin output recovered from memory) and found a running `dnsmasq` process with PID `38687`. That links the installer activity to the actual running service instance captured in RAM.  
**Answer:** `dnsmasq,38687`

---

## 🚩 Flag 7 — Tricked Workstation Hostname  
**Question:** Which workstation was given the malicious network configuration?  
**Context:** The malicious config included a hostname — find it in memory.  
**Explanation:**  
I searched the memory image for fragments of the malicious network configuration (iptables rules, dnsmasq entries, config blobs). Within those fragments appeared a hostname string associated with the modified settings. The hostname found in those network fragments is `Parallax-5-WS-3`, indicating the workstation that accepted the attacker’s config.  
**Answer:** `Parallax-5-WS-3`

---

## 🚩 Flag 8 — Portal Username  
**Question:** From that workstation, who accessed the internal portal (username)?  
**Context:** Look for portal access URLs or query strings in memory that carry a username parameter.  
**Explanation:**  
I scanned for HTTP request fragments and common login parameter patterns (`user=`, `username=`, `login=`). Among captured URL/query fragments was a portal access containing a username parameter. That extracted username value is `mike.sullivan`. Because it was found in live HTTP fragments in memory, it likely represents a recently used credential or session.  
**Answer:** `mike.sullivan`

---

## 🚩 Flag 9 — Update Endpoint  
**Question:** From which web endpoint was the malicious update downloaded?  
**Context:** Identify the exact endpoint path the workstation requested to download the malicious update executable.  
**Explanation:**  
Memory contained HTTP download fragments and the portal-supplied update link. The download request pointed to an executable named `AetherDesk-v74-77.exe` in a versioned update folder. The path string recovered from these HTTP fragments is `/win10/update/CogSoftware/AetherDesk-v74-77.exe`. This is the endpoint the victim hit to retrieve the malicious installer.  
**Answer:** `/win10/update/CogSoftware/AetherDesk-v74-77.exe`

---

## 🚩 Flag 10 — Redirect Domain and IP  
**Question:** Which original domain was redirected and to what IP:port did it point?  
**Context:** Attacker modified DNS/dnsmasq to redirect legitimate updates to a malicious server.  
**Explanation:**  
I recovered dnsmasq and temporary config fragments from memory and inspected the content for domain mappings. The config showed that `updates.cogwork-1.net` — the legitimate update domain — was redirected to the attacker-controlled endpoint `13.62.49.86:7477`. Those mappings were present in deleted-temp config fragments and in-memory dnsmasq data structures, showing the exact domain and the redirect target used in the supply-chain step.  
**Answer:** `updates.cogwork-1.net,13.62.49.86:7477`

---
**Next challenge writeup:** [Holmes — The Payload](./holmes_the_payload.md)
