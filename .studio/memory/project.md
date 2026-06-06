# Analyst-system — Project Memory

## Decisioni architetturali

### Librarian pattern (2026-06-07)
754 skill cybersecurity caricate tutte in `.claude/skills/` saturavano il contesto.
Soluzione: rimozione symlink, indice pre-computato `skills-index.json`, skill router (librarian).
Il librarian carica al massimo 5 skill per query, solo su richiesta confermata.

### `.studio/agents/` come source of truth (2026-06-07)
Agenti spostati da `.claude/agents/` a `.studio/agents/`. `.claude/agents/` contiene solo symlink.
Motivazione: separare la configurazione studio dalla configurazione Claude Code.
Regola: creare sempre in `.studio/`, poi symlinkare.

### Python stdlib only (vincolo pre-esistente)
Tutti gli script in `backend/` usano solo stdlib Python 3.
Motivazione: gli agenti Claude non hanno pip install disponibile nell'ambiente runtime.
Non fare eccezioni — usare `urllib.request` per HTTP, `subprocess` per tool di sistema.

### report-builder.py come utility condivisa (2026-06-07)
Invece di far generare il markdown a ogni agente manualmente, tutti usano `report-builder.py`.
Input: glob di JSON da `backend/outputs/`. Output: markdown strutturato con severity ranking.
Campi findings standard: `type`, `severity`, `description`, `guidance` + opzionali.

### security-audits/ root versionata, sottocartelle gitignored (2026-06-07)
I report executive (`analyst`) a root di `security-audits/` sono versionati — contengono sintesi.
I report di singolo dipartimento (`security-audits/network/`, etc.) sono gitignored — dati grezzi.

## Note operative

- API key opzionali: `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY` — gli script degradano senza
- Targets live: bagheera.mowgli.studio (API), mowgli.studio, baloo.mowgli.studio
- GitHub: https://github.com/meowgl1/analyst-system (push 2026-06-07)
- Frontend dashboard: Next.js 15, porta 3001

## Versioni

| Data | Versione | Highlights |
|---|---|---|
| 2026-06-07 | v2.1 | 11 agenti, 27 script, 8 dipartimenti, librarian, GitHub |
| pre-2026-06-07 | v1.x | 6 agenti, 8 script, 4 dipartimenti |
