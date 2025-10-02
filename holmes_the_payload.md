# Holmes CTF 2025: *The Payload*
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
- 🟥 ["The Tunnel Without Walls"](./holmes_the_tunnel_without_walls.md)
- 🟥 ["The Payload"](./holmes_the_payload.md)

---

**Prompt:** With the malware extracted, Holmes inspects its logic. The strain spreads silently across the entire network. Its goal? Not destruction, something more persistent…friends. NOTE: The downloaded file is active malware. Take the necessary precautions when attempting this challenge.

**Summary:** A malware sample that spreads laterally and focuses on stealthy persistence was extracted for defensive analysis. The objectives are to reverse-engineer its behavior (imports, GUIDs/COM usage, opcodes, and crypto/key derivation), recover and decrypt its killswitch domain, and verify findings in a safe lab. Finally, block that domain inside an isolated Docker test network so the sample cannot phone home during analysis.


**🟥 Challenge Difficulty:** *HARD*

---

## 📋 TL;DR (Answers)

- **COM Init:** `ole32.dll`
- **GUID:** `dabcd999-1234-4567-89ab-1234567890ff`
- **Interop:** `Interop`
- **First Call:** `ff 50 68`
- **Keygen Consts:** `7, 42h`
- **Decrypt Call:** `ff 50 58`
- **DNS Resolve:** `getaddrinfo`
- **Share Enum:** `NetShareEnum`
- **Payload Run:** `ff 50 60`
- **Final Flag:** `HTB{Eternal_Companions_Reunited_Again}`


---

## Flags & Walkthrough


**IN PROGRESS**
