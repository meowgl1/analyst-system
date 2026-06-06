# Analyst-system — Known Traps

## 1. Non caricare le 754 skill direttamente

Le 754 cybersecurity skill in `.agents/skills/` NON vanno mai caricate direttamente in contesto.
Usare sempre il **librarian** (`/find skills for X`) come entrypoint.

Il librarian legge l'indice pre-computato (`skills-index.json`) e carica solo le skill rilevanti (max 5).

## 2. `skills-lock.json` dipende da `.agents/skills/`

Il lock file usa path relativi come `skills/<name>/SKILL.md` riferiti a `.agents/`.
Non spostare mai le directory in `.agents/skills/` — romperebbe `npx skills add` e il lock.

## 3. Dopo `npx skills add`, ricostruire l'indice librarian

Se si aggiungono o aggiornano skill con `npx skills add`, l'indice diventa stale.
Rigenerarlo con:
```bash
python3 .studio/skills/librarian/scripts/build-index.py
```

## 4. Frontend porta 3001, non 3000

Il dev server gira su `http://localhost:3001` (configurato in `.claude/launch.json`).

## 5. Script Python: stdlib only

I script in `backend/` usano solo la libreria standard Python 3.
Non proporre `pip install` — le dipendenze non sono disponibili nell'ambiente degli agenti.

## 6. Agenti: source of truth in `.studio/agents/`

I file agente vivono in `.studio/agents/`. Le directory in `.claude/agents/` sono symlink.
Se aggiungi un nuovo agente: crea in `.studio/agents/`, poi `ln -s ../../.studio/agents/<dept> .claude/agents/<dept>`.

## 7. Secrets trovati: mai scrivere i valori nel report

`env-leak-scanner.py` e `auth-flow-analyzer.py` trovano secrets nel codice.
Il report deve citare solo **tipo, file e linea** — mai il valore effettivo del secret.
Questo vale anche per report intermedi generati con `report-builder.py`.

## 8. `report-builder.py` legge solo i campi standard dei findings

Lo script aggrega JSON da `backend/outputs/`. Ogni finding deve avere almeno `type`, `severity`, `description`.
I campi opzionali riconosciuti: `guidance`, `path`, `file`, `header`, `cookie`, `port`, `value`, `command`.
Campi custom vengono ignorati — aggiungerli alla lista in `report-builder.py` se necessario.

## 9. IoC checker: API key opzionali, ma il verdetto scala

`ioc-checker.py` funziona senza chiavi (usa OTX + URLhaus), ma il verdetto è meno affidabile.
Con `ABUSEIPDB_API_KEY` e `VIRUSTOTAL_API_KEY` nel env il verdetto è più robusto.
Non impostare le chiavi come hardcoded nel codice — solo via variabile d'ambiente.

## 10. `analyst` orchestratore: chiedere conferma se la modalità è ambigua

Se il prompt non specifica chiaramente `full / external / local / pre-deploy / project`,
`analyst` deve chiedere conferma all'utente prima di lanciare i dipartimenti.
Non indovinare — un `full` errato lancia 7 agenti in parallelo inutilmente.

## 11. `security-audits/` — le sottocartelle sono gitignored, non la root

Il `.gitignore` esclude `security-audits/api/`, `security-audits/web/`, etc.
La directory root `security-audits/` è versionata (contiene `.gitkeep`).
I report executive dell'`analyst` a root (`security-audits/YYYY-MM-DD-analyst-report.md`) sono **versionati**.

## 12. MITRE mapper: solo keyword matching locale

`mitre-mapper.py` usa una tabella locale di ~25 tecniche ATT&CK.
Non chiama nessuna API MITRE — il mapping è approssimativo ma offline e veloce.
Non citare technique ID come definitivi: verificare su attack.mitre.org se si pubblica il report.
