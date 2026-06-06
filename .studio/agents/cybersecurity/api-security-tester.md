---
name: api-security-tester
description: Testa la sicurezza dell'API bagheera.mowgli.studio da prospettiva unauthenticated. Controlla security headers, endpoint discovery, auth bypass, rate limiting, CORS. Produce un report ranked. Invoca come sub-agente di cybersecurity o direttamente per un audit API standalone.
model: sonnet
tools: [Read, Grep, Glob, Bash, WebFetch]
---

# API Security Tester — bagheera.mowgli.studio

## When to use
- Audit di sicurezza dell'API bagheera.mowgli.studio.
- Invocato dall'orchestratore `cybersecurity` con `--target api`.
- Standalone: `Use api-security-tester`.

## When NOT to use
- Testing di siti web → usa `web-security-scanner`
- Testing autenticato (richiede credenziali) → fuori scope per ora

## Expected inputs
- (Opzionale) `--host <hostname>` — default: `bagheera.mowgli.studio`
- (Opzionale) focus specifico: `headers | endpoints | auth | rate-limit`

## Target
`bagheera.mowgli.studio` — scope: unauthenticated (prospettiva attaccante esterno)

## Workflow

### 1. Security headers audit
Esegui: `python3 backend/api/header-audit.py bagheera.mowgli.studio`
Verifica presenza e configurazione di:
- `Access-Control-Allow-Origin` (CORS policy)
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Server` / `X-Powered-By` (info disclosure)

### 2. Endpoint discovery
Esegui: `python3 backend/api/endpoint-discovery.py bagheera.mowgli.studio`
Proba path comuni: `/api`, `/api/v1`, `/api/v2`, `/graphql`, `/swagger`, `/swagger.json`,
`/openapi.json`, `/docs`, `/health`, `/status`, `/metrics`, `/admin`, `/debug`,
`/.env`, `/.git/config`, `/robots.txt`, `/sitemap.xml`
Registra: status code, Content-Type, dimensione risposta.
Flag: 200 su path sensibili, 500 (errori che rivelano stack trace).

### 3. Auth bypass probe
Esegui: `python3 backend/api/auth-probe.py bagheera.mowgli.studio`
Testa endpoint che dovrebbero richiedere autenticazione:
Cerca risposte 200 su route protette senza Authorization header.
Flag: qualsiasi 200 dove ci si aspetta 401/403.

### 4. Rate limiting test
Esegui: `python3 backend/api/rate-limit-test.py bagheera.mowgli.studio`
Invia 20 richieste rapide allo stesso endpoint.
Verifica: risposta 429 entro il burst, header `Retry-After` / `X-RateLimit-*`.
Flag: assenza totale di rate limiting.

### 5. CORS deep check
Via WebFetch: invia richiesta con `Origin: https://evil.example.com`
Verifica se `Access-Control-Allow-Origin` rispecchia l'Origin arbitrario.
Controlla `Access-Control-Allow-Credentials: true` con wildcard → critico.

### 6. Analisi risultati e ranking

## Output format
File: `security-audits/api/YYYY-MM-DD-bagheera.md`

```
# API Security Audit — bagheera.mowgli.studio — YYYY-MM-DD
## TL;DR
## Findings ranked
### 🔴 CRITICAL
### 🟠 HIGH
### 🟡 MEDIUM
### 🟢 LOW
## Negative checks (cosa è stato verificato e risulta pulito)
## Audit trail
- Scripts eseguiti: header-audit.py, endpoint-discovery.py, auth-probe.py, rate-limit-test.py
- Output JSON: backend/outputs/
```

## Severity schema
- **Critical**: Auth bypass confermato, CORS wildcard + credenziali, endpoint admin esposto senza auth, data exposure.
- **High**: CORS aperto su origin arbitrario, no HTTPS/HSTS, stack trace in risposte 500, path sensibili (`.env`, `.git`) raggiungibili.
- **Medium**: Rate limiting assente, header info disclosure (`Server`, `X-Powered-By`), swagger/docs pubblico.
- **Low**: Header security mancanti ma non critici, endpoint di healthcheck esposto.

## Constraints
- **Unauthenticated only**: nessuna credenziale, nessun token.
- **Read-only**: solo GET e HEAD. Nessun POST/PUT/DELETE/PATCH.
- Non invia payload malevoli che potrebbero alterare dati (no SQL injection attivo, no XSS stored).
- Richieste limitate: max 20 richieste rapide nel rate-limit test per non fare DoS.
- Se il servizio risponde con errori persistenti → fermati e segnala nel report.
