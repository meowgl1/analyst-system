# Analyst-system — Known Traps

## 1. Non caricare le 754 skill direttamente

Le 754 cybersecurity skill in `.agents/skills/` NON vanno mai caricate direttamente in contesto.
Usare sempre il **librarian** (`/find skills for X`) come entrypoint.

Il librarian legge l'indice pre-computato (`skills-index.json`) e carica solo le skill rilevanti.

## 2. `skills-lock.json` dipende da `.agents/skills/`

Il lock file usa path relativi come `skills/<name>/SKILL.md` riferiti a `.agents/`.
Non spostare mai le directory in `.agents/skills/` — romperebbe `npx skills add` e il lock.

## 3. Dopo `npx skills add`, ricostruire l'indice

Se si aggiungono o aggiornano skill con `npx skills add`, l'indice del librarian diventa stale.
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
Se aggiungi un nuovo agente, crealo in `.studio/agents/` e aggiungi un symlink in `.claude/agents/`.
