# Backend / Web Security Scripts

Script di sicurezza per testare i siti `mowgli.studio` e `baloo.mowgli.studio`.
Tutti i test sono **read-only** (nessun submit di form, nessuna modifica).

## Script

| Script | Cosa fa | Step nell'audit |
|---|---|---|
| `security-headers.py` | Verifica tutti gli HTTP security headers | 1 |
| `form-scanner.py` | Crawl pagine, cataloga form/input, verifica CSRF token | 2 |
| `cookie-audit.py` | Analizza cookie flags (HttpOnly, Secure, SameSite) | 3 |
| `csp-analyzer.py` | Parsing e grading della Content-Security-Policy | 4 |

## Uso

```bash
# Audit su un singolo target (eseguito dall'agente web-security-scanner)
python3 backend/web/security-headers.py mowgli.studio
python3 backend/web/form-scanner.py mowgli.studio
python3 backend/web/cookie-audit.py mowgli.studio
python3 backend/web/csp-analyzer.py mowgli.studio

# Poi ripeti per baloo.mowgli.studio
python3 backend/web/security-headers.py baloo.mowgli.studio
# ...

# Output JSON in backend/outputs/YYYY-MM-DD-<script>-<host>.json
```

## Requisiti
- Python 3.8+ (solo stdlib — no pip install richiesto)
- Permesso `Bash(python3:*)` in `.claude/settings.json`

## Limiti
- Il form-scanner crawla max 10 pagine per sito
- Analisi statica only — nessun payload XSS inviato
- Nessun submit di form
