# Honeypot Lab — Live Breach & Incident Response (Azure + Microsoft Sentinel)

> ⚠️ **Context**: lab fully contained within my personal Azure environment (isolated resource group `rg-honeypot-lab`). Fictitious data, no real information. The attack was carried out by me from my own Kali Linux VM, in a controlled and authorized manner (same subscription, same owner). No third-party systems were involved.

## 📌 Objective

Build a realistic honeypot in Azure (Windows VM + MySQL database with fictitious data), deliberately expose it with vulnerable configurations, attack it end-to-end simulating a real threat actor, and verify the entire incident response lifecycle — detection, analysis, containment, eradication — using Microsoft Sentinel for detection.

Unlike a "lab-only" exercise, here the detection infrastructure had to detect a live attack (carried out by me) on real cloud infrastructure, not a replay of static data.

## 🧩 Architecture

```
Kali Linux (attacker)    ───attack──▶ Azure VM "web-prod-01" (Windows 11, honeypot)
                                              │
                                        MySQL 8.0.46 (corpdb)
                                              │
                                     general_query.log
                                              │
                                   Azure Monitor Agent (DCR)
                                              │
                                  Log Analytics Workspace (law-honeypot-lab)
                                              │
                                     Microsoft Sentinel
                                   (3 custom detection rules)
                                              │
                                  Automatic incidents in Defender XDR
```

## 🛠 Technologies and Tools

- **Microsoft Azure**: VM Windows 11 (Standard_D2als_v6), Virtual Network, Network Security Group, Azure Bastion
- **Microsoft Defender for Cloud**: Server plan (Plan 1) for VM protection
- **Azure Monitor Agent + Data Collection Rule**: custom log collection pipeline
- **Log Analytics Workspace**: storage and KQL queries
- **Microsoft Sentinel** (via the unified Microsoft Defender portal): custom detection rules, incident management
- **MySQL Server 8.0.46**: honeypot database with fictitious data
- **Kali Linux**: attack platform (nmap, mysql client, mysqldump)

## ⚙️ Lab Phases

### Phase 1-2 — Building the Honeypot
- Windows 11 VM created in a dedicated resource group (`rg-honeypot-lab`), initially with no public ports exposed
- Microsoft Defender for Cloud (Server plan) enabled for Azure-native security telemetry — an alternative to Microsoft Defender for Endpoint, which would require an M365 E5 license not available in this context
- MySQL Server 8.0.46 installed, `corpdb` database populated with fictitious data: customers, orders, payments, and a `credentials` table with **plaintext** passwords — a deliberate bad security practice, used as bait
- MySQL query log (`general_query.log`) permanently enabled via configuration file (`my.ini`), to record every connection and query

### Phase 3 — Logging Pipeline to Sentinel
- Created a dedicated Log Analytics Workspace (`law-honeypot-lab`)
- Created a custom table (`MySQLHoneypotLog_CL`) and a Data Collection Rule that reads `general_query.log` from the VM and forwards it to the workspace
- Verified the pipeline end-to-end with test KQL queries

### Phase 4 — Writing the Detections
Created 3 custom detection rules in Microsoft Sentinel, each mapped to a MITRE ATT&CK tactic:

| Rule | KQL Query | Severity | MITRE ATT&CK |
|---|---|---|---|
| Access to credentials table | `MySQLHoneypotLog_CL \| where RawData has "credentials"` | High | Credential Access |
| Suspicious connection volume | `... \| summarize ConnectionCount = count() by bin(TimeGenerated, 1m) \| where ConnectionCount > 10` | Medium | Discovery |
| Database exploratory queries | `... \| where RawData has_any (dynamic(["SHOW TABLES","DESCRIBE","information_schema"]))` | Medium | Discovery |

### Phase 5 — Deliberate Weakening (Weaken & Expose)
To make the honeypot attackable:
- Created a local administrator account with a weak password
- Enabled the Guest account with a weak password
- Disabled the Windows firewall on all profiles
- Created a **MySQL root user with no password**, accessible from any host (`'root'@'%'`)
- Modified the Network Security Group to expose ports 3306 (MySQL) and 3389 (RDP) — restricted to my public IP to keep the lab controlled, rather than open to the whole Internet

### Phase 6-7 — Attack and Detection
See full details in [`docs/attack-and-detection.md`](docs/attack-and-detection.md).

Summary: reconnaissance scan (`nmap`), direct access to MySQL as root without needing to guess any password, database exploration, full exfiltration with `mysqldump`.

**Result**: both detection rules fired automatically, generating 2 incidents in Microsoft Defender:
- 🔴 **"Access to the credentials table on the MySQL honeypot"** — High severity
- 🟠 **"Exploratory queries on the honeypot database"** — Medium severity

### Phase 8-9 — Containment and Eradication
- **Containment**: removed the NSG rules exposing the VM — verified with nmap that the ports show as "filtered" again
- **Eradication**: removed the weak administrator account, disabled Guest, re-enabled the Windows firewall, removed the MySQL root user with no password

## 📊 Result

Full incident response cycle demonstrated first-hand, from both sides:
- **Red team**: reconnaissance → exploitation → data discovery → exfiltration
- **Blue team**: custom logging pipeline → detection engineering → automatic detection → analysis → containment → eradication

## 🧱 Observations and Limitations

- The attack was carried out from a known IP (mine), not by a real threat actor — the connection-volume detection was not fully exercised (it would have required a real automated scan/brute force)
- Entity mapping (device) in the Sentinel rules was not completed due to a temporary Defender portal error — the rules work anyway, but without automatic device context enrichment
- Microsoft Defender for Endpoint (MDE) was not used because an M365 E5 license was not available — Microsoft Defender for Cloud (Server plan, Azure-native) proved to be a valid and sufficient alternative for this scenario
