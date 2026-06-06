## Doing

## Next

- [ ] Testare ogni script backend manualmente (`python3 backend/<dept>/script.py --help`)
- [ ] Aggiungere `.gitkeep` alle sottocartelle `security-audits/` mancanti
- [ ] Frontend dashboard: aggiungere pannelli per i nuovi tipi di report (network, threat-intel, cloud, identity)
- [ ] Librarian: verificare che `skills-index.json` sia aggiornato dopo l'ultimo `npx skills add`
- [ ] Aggiungere un `changelog/2026-06-07-v2.md` con la descrizione della v2

## Blocked

## Done — giugno 2026

- [x] Studio v1: installazione struttura locale (.studio/, librarian, symlink agenti)
- [x] Rimossi 754 symlink da `.claude/skills/` — ora si usa il librarian
- [x] `skills-index.json` generato (452KB, 45 subdomini, 754 skill)
- [x] Agenti spostati in `.studio/agents/`, symlink in `.claude/agents/`
- [x] v2: 4 nuovi dipartimenti (network, threat-intel, cloud, identity)
- [x] v2: 11 nuovi script backend (dns-enum, port-profiler, connection-monitor, ioc-checker, mitre-mapper, osint-domain, dockerfile-audit, env-leak-scanner, vercel-config-audit, auth-flow-analyzer, permission-scanner)
- [x] v2: 3 script forensics (persistence-scanner, binary-verifier, log-analyzer)
- [x] v2: 2 script dependency-audit (package-analyzer, lockfile-auditor)
- [x] v2: report-builder.py — utility condivisa JSON → markdown
- [x] v2: 5 nuovi agenti (analyst, network-analyst, threat-hunter, cloud-auditor, identity-auditor)
- [x] v2: symlink .claude/agents/ per i 4 nuovi dipartimenti + analyst.md
- [x] v2: README.md completo (11 agenti, 27 script, architettura, guide)
- [x] Push su GitHub: https://github.com/meowgl1/analyst-system
