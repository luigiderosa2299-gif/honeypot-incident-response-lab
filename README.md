# Honeypot Lab — Live Breach & Incident Response (Azure + Microsoft Sentinel)

> ⚠️ **Contesto**: laboratorio interamente contenuto nel mio ambiente Azure personale (resource group isolato `rg-honeypot-lab`). Dati fittizi, nessuna informazione reale. L'attacco è stato condotto da me stesso dalla mia VM Kali Linux, in modo controllato e autorizzato (stessa sottoscrizione, stesso proprietario). Nessun sistema di terzi è stato coinvolto.

## 📌 Obiettivo

Costruire un honeypot realistico in Azure (VM Windows + database MySQL con dati fittizi), esporlo deliberatamente con configurazioni vulnerabili, attaccarlo end-to-end simulando un vero threat actor, e verificare l'intero ciclo di vita dell'incident response — rilevamento, analisi, contenimento, eradicazione — usando Microsoft Sentinel per la detection.

A differenza di un lab "in laboratorio", qui l'infrastruttura di detection ha dovuto rilevare un attacco reale (condotto da me) su un'infrastruttura cloud reale, non un replay di dati statici.

## 🧩 Architettura

```
Kali Linux (attaccante)  ──attacco──▶  Azure VM "web-prod-01" (Windows 11, honeypot)
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
                                   (3 regole di detection custom)
                                              │
                                  Incidenti automatici in Defender XDR
```

## 🛠 Tecnologie e Strumenti

- **Microsoft Azure**: VM Windows 11 (Standard_D2als_v6), Virtual Network, Network Security Group, Azure Bastion
- **Microsoft Defender for Cloud**: piano Server (Piano 1) per la protezione della VM
- **Azure Monitor Agent + Data Collection Rule**: pipeline di raccolta log personalizzata
- **Log Analytics Workspace**: storage e query KQL
- **Microsoft Sentinel** (via portale unificato Microsoft Defender): regole di detection custom, gestione incidenti
- **MySQL Server 8.0.46**: database honeypot con dati fittizi
- **Kali Linux**: piattaforma di attacco (nmap, mysql client, mysqldump)

## ⚙️ Fasi del laboratorio

### Fase 1-2 — Costruzione dell'honeypot
- VM Windows 11 creata in un resource group dedicato (`rg-honeypot-lab`), inizialmente senza porte pubbliche esposte
- Microsoft Defender for Cloud (piano Server) attivato per telemetria di sicurezza nativa Azure — alternativa a Microsoft Defender for Endpoint, che richiederebbe una licenza M365 E5 non disponibile in questo contesto
- MySQL Server 8.0.46 installato, database `corpdb` popolato con dati fittizi: clienti, ordini, pagamenti, e una tabella `credentials` con password **in chiaro** — cattiva pratica di sicurezza voluta, usata come esca
- Query log MySQL (`general_query.log`) attivato in modo permanente via file di configurazione (`my.ini`), per registrare ogni connessione e query

### Fase 3 — Pipeline di logging verso Sentinel
- Creato un Log Analytics Workspace dedicato (`law-honeypot-lab`)
- Creata una tabella personalizzata (`MySQLHoneypotLog_CL`) e una Data Collection Rule che legge `general_query.log` dalla VM e lo inoltra al workspace
- Verificata la pipeline end-to-end con query KQL di test

### Fase 4 — Scrittura delle detection
Create 3 regole di rilevamento personalizzate in Microsoft Sentinel, ciascuna mappata a una tattica MITRE ATT&CK:

| Regola | Query KQL | Gravità | MITRE ATT&CK |
|---|---|---|---|
| Accesso tabella credentials | `MySQLHoneypotLog_CL \| where RawData has "credentials"` | Alta | Credential Access |
| Volume connessioni sospette | `... \| summarize ConnectionCount = count() by bin(TimeGenerated, 1m) \| where ConnectionCount > 10` | Media | Discovery |
| Query esplorative database | `... \| where RawData has_any (dynamic(["SHOW TABLES","DESCRIBE","information_schema"]))` | Media | Discovery |

### Fase 5 — Indebolimento deliberato (Weaken & Expose)
Per rendere l'honeypot attaccabile:
- Creato un account amministratore locale con password debole
- Account Guest abilitato con password debole
- Disabilitato il firewall di Windows su tutti i profili
- Creato un utente **root MySQL senza password**, accessibile da qualsiasi host (`'root'@'%'`)
- Modificato il Network Security Group per esporre le porte 3306 (MySQL) e 3389 (RDP) — limitato al mio IP pubblico per mantenere il lab controllato, invece che aperto a tutto Internet

### Fase 6-7 — Attacco e Detection
Vedi dettaglio completo in [`docs/attack-and-detection.md`](docs/attack-and-detection.md).

Riassunto: scansione di ricognizione (`nmap`), accesso diretto a MySQL come root senza bisogno di indovinare alcuna password, esplorazione del database, esfiltrazione completa con `mysqldump`.

**Risultato**: entrambe le regole di detection si sono attivate automaticamente, generando 2 incidenti in Microsoft Defender:
- 🔴 **"Accesso alla tabella credentials sull'honeypot MySQL"** — Gravità Alta
- 🟠 **"Query esplorative sul database honeypot"** — Gravità Media

### Fase 8-9 — Contenimento ed Eradicazione
- **Contenimento**: rimosse le regole NSG che esponevano la VM — verificato con nmap che le porte risultano nuovamente "filtered"
- **Eradicazione**: rimosso l'account amministratore debole, disattivato Guest, riattivato il firewall di Windows, rimosso l'utente root MySQL senza password

## 📊 Risultato

Ciclo completo di incident response dimostrato in prima persona, da entrambi i lati:
- **Red team**: ricognizione → exploitation → scoperta dati → esfiltrazione
- **Blue team**: pipeline di logging custom → detection engineering → rilevamento automatico → analisi → contenimento → eradicazione

## 🧱 Osservazioni e limiti

- L'attacco è stato condotto da un IP noto (il mio), non da un vero threat actor — la detection sul volume di connessioni non è stata esercitata a pieno (avrebbe richiesto un vero scan/brute force automatizzato)
- Il mapping delle entità (dispositivo) nelle regole Sentinel non è stato completato per un errore temporaneo del portale Defender — le regole funzionano comunque, ma senza arricchimento automatico del contesto dispositivo
- Microsoft Defender for Endpoint (MDE) non è stato usato per via di una licenza M365 E5 non disponibile — Microsoft Defender for Cloud (piano Server, nativo Azure) si è dimostrata un'alternativa valida e sufficiente per questo scenario
