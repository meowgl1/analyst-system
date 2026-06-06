---
name: cybersecurity-librarian
description: >
  Skill router for 754 cybersecurity skills across 30 subdomains. Searches the pre-computed
  index by subdomain, tags, description keywords, skill name, or NIST CSF codes and returns
  the 1-5 most relevant skills. Use before loading any cybersecurity skill. Invoke with:
  "find skills for X", "which skill handles Y", "skills for NIST DE.CM-01",
  "what skill does Z", "load skill for X".
triggers:
  - find skill
  - which skill
  - skill for
  - skills for
  - cybersecurity skill
  - load skill
  - skill che
  - quale skill
---

# Cybersecurity Skill Librarian

Gestisce 754 cybersecurity skill in 30+ sottodomini. Funziona come entrypoint per tutte le ricerche di skill — non caricare mai skill direttamente dalla library senza passare per qui.

## Workflow

### 1. Leggi l'indice

Leggi il file:
```
.studio/skills/librarian/skills-index.json
```

Contiene tutti i metadati delle 754 skill (nome, descrizione, subdomain, tags, NIST CSF).
Caricalo una volta e usalo per tutta la sessione.

### 2. Cerca

Usa questa priorità di match:

| Tipo di query | Strategia |
|---|---|
| Dominio ("API security", "cloud forensics") | Filtra per `subdomain` |
| Task ("analizzare malware", "detect lateral movement") | Match su `description` + `tags` |
| Tool specifico ("cobalt strike", "wireshark", "falco") | Match su `name` + `tags` |
| NIST CSF ("DE.CM-01", "RS.AN-03") | Match su `nist_csf` array |
| Broad ("threat hunting") | Subdomain filter, poi rank per rilevanza della descrizione |

Ranking: exact subdomain match > tag exact match > description keyword > partial name match.

### 3. Restituisci una tabella

```markdown
| Skill | Subdomain | Perché rilevante |
|---|---|---|
| nome-skill | subdomain | 1-riga di motivo |
```

Mostra sempre **tra 1 e 5 risultati**. Non mostrarne mai di più — meno è meglio se la query è specifica.

Aggiungi sotto la tabella:

> Vuoi caricare una di queste? Dimmi il nome e carico la SKILL.md completa.

### 4. Carica su conferma

Quando l'utente conferma una skill per nome, leggi:
```
.studio/skills/librarian/library/<nome-skill>/SKILL.md
```

Carica **una skill alla volta**, massimo 5 per sessione.

---

## Subdomini disponibili

```
cloud-security (63)       threat-hunting (56)       threat-intelligence (50)
network-security (43)     web-application-security (42)  malware-analysis (39)
digital-forensics (37)    soc-operations (33)        identity-access-management (33)
container-security (29)   security-operations (28)   ot-ics-security (28)
api-security (28)         incident-response (26)     vulnerability-management (25)
red-teaming (24)          penetration-testing (20)   zero-trust-architecture (17)
endpoint-security (17)    devsecops (17)             phishing-defense (15)
cryptography (15)         ransomware-defense (13)    mobile-security (13)
threat-detection (7)      compliance-governance (4)  application-security (4)
supply-chain-security (3) deception-technology (3)   wireless-security (2)
```

---

## Regole

- **MAI** caricare più di 5 skill in contesto contemporaneamente
- **SEMPRE** cercare nell'indice prima — non browsare `library/` direttamente
- Se nessuna skill corrisponde, dillo esplicitamente — non inventare nomi di skill
- Se l'indice è stale (skill aggiunta ma non trovata), suggerire:
  ```bash
  python3 .studio/skills/librarian/scripts/build-index.py
  ```
