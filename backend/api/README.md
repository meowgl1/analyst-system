# Backend / API Security Scripts

Script di sicurezza per testare l'API `bagheera.mowgli.studio`.
Tutti i test sono **unauthenticated** (prospettiva attaccante esterno) e **read-only** (solo GET/HEAD).

## Script

| Script | Cosa fa | Step nell'audit |
|---|---|---|
| `header-audit.py` | Security headers + CORS + info disclosure | 1 |
| `endpoint-discovery.py` | Proba ~40 path comuni, annota status code | 2 |
| `auth-probe.py` | Testa ~30 route protette senza auth, cerca bypass | 3 |
| `rate-limit-test.py` | Burst di richieste per verificare rate limiting | 4 |

## Uso

```bash
# Audit completo (eseguito dall'agente api-security-tester)
python3 backend/api/header-audit.py bagheera.mowgli.studio
python3 backend/api/endpoint-discovery.py bagheera.mowgli.studio
python3 backend/api/auth-probe.py bagheera.mowgli.studio
python3 backend/api/rate-limit-test.py bagheera.mowgli.studio

# Output JSON in backend/outputs/YYYY-MM-DD-<script>-bagheera.mowgli.studio.json
```

## Requisiti
- Python 3.8+ (solo stdlib — no pip install richiesto)
- `curl` disponibile nel PATH (usato da header-audit.py)
- Permesso `Bash(python3:*)` e `Bash(curl:*)` in `.claude/settings.json`

## Limiti di sicurezza
- **Max 30 richieste** nel rate-limit test (hard limit anti-DoS)
- **Solo GET/HEAD** — nessuna mutazione
- Nessun payload malevolo inviato
