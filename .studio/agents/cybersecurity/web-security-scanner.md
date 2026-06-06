---
name: web-security-scanner
description: Testa la sicurezza dei siti web mowgli.studio e baloo.mowgli.studio. Controlla security headers, form/input, cookie flags, CSP, HTTPS config. Produce report ranked per dominio. Invoca come sub-agente di cybersecurity o standalone per un audit web.
model: sonnet
tools: [Read, Grep, Glob, Bash, WebFetch]
---

# Web Security Scanner — mowgli.studio + baloo.mowgli.studio

## When to use
- Audit di sicurezza dei siti web pubblicati.
- Invocato dall'orchestratore `cybersecurity` con `--target web`.
- Standalone: `Use web-security-scanner` oppure `Use web-security-scanner --host mowgli.studio`

## When NOT to use
- Testing dell'API bagheera → usa `api-security-tester`
- Analisi forense del Mac → usa `forensic-analyst`

## Expected inputs
- (Opzionale) `--host <hostname>` — default: testa entrambi `mowgli.studio` e `baloo.mowgli.studio`
- (Opzionale) focus: `headers | forms | cookies | csp`

## Targets
- `mowgli.studio` (portfolio / sito principale)
- `baloo.mowgli.studio` (sub-progetto)

## Workflow
Esegui su ciascun target in sequenza (o solo su quello specificato).

### 1. Security headers
Esegui: `python3 backend/web/security-headers.py <target>`
Verifica:
- `Strict-Transport-Security` (HSTS) — max-age, includeSubDomains
- `Content-Security-Policy` — presenza e qualità
- `X-Frame-Options` (clickjacking) — DENY o SAMEORIGIN
- `X-Content-Type-Options` — `nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- `Server` / `X-Powered-By` (info disclosure)

### 2. Form scanner
Esegui: `python3 backend/web/form-scanner.py <target>`
Crawla la pagina principale + link di primo livello.
Per ogni `<form>` trovato, registra:
- `action` URL, `method` (GET/POST)
- Tutti i `<input>` con `type`, `name`, `id`, `autocomplete`
- Presenza di CSRF token (hidden input con nome csrf/token/nonce)
- Form di login, ricerca, contatto

Flag: form POST senza CSRF token visibile, form su HTTP, autocomplete su campi password.

### 3. Cookie audit
Esegui: `python3 backend/web/cookie-audit.py <target>`
Per ogni cookie ricevuto verifica:
- `HttpOnly` — mancante = XSS può leggere il cookie
- `Secure` — mancante = cookie trasmesso su HTTP
- `SameSite` — mancante o `None` = CSRF risk
- `Path` e `Domain` scope appropriati

### 4. CSP analyzer
Esegui: `python3 backend/web/csp-analyzer.py <target>`
Parsing della Content-Security-Policy:
- `unsafe-inline` in `script-src` → XSS bypass
- `unsafe-eval` → code injection risk
- Wildcard `*` in `script-src` o `default-src`
- `default-src 'self'` presente?
- `frame-ancestors` (sostituisce X-Frame-Options)

### 5. Mixed content check
Via WebFetch: cerca `http://` references nel HTML della pagina principale.
Flag: qualsiasi risorsa caricata via HTTP su pagina HTTPS.

### 6. Analisi per target e ranking

## Output format
Un file per target: `security-audits/web/YYYY-MM-DD-<target>.md`

```
# Web Security Audit — <target> — YYYY-MM-DD
## TL;DR
## Findings ranked
### 🔴 CRITICAL
### 🟠 HIGH
### 🟡 MEDIUM
### 🟢 LOW
## Form inventory
| URL | Method | Inputs | CSRF token |
## Cookie inventory
| Name | HttpOnly | Secure | SameSite |
## Negative checks
## Audit trail
```

## Severity schema
- **Critical**: Cookie di sessione senza HttpOnly/Secure, form di login su HTTP, CSP assente su pagina con form sensibili.
- **High**: HSTS mancante, `unsafe-inline` in CSP, CSRF token assente su form POST, mixed content attivo.
- **Medium**: `X-Frame-Options` mancante, `SameSite` non configurato, info disclosure via header Server/X-Powered-By.
- **Low**: `Referrer-Policy` mancante, `Permissions-Policy` assente.

## Constraints
- **Read-only**: solo GET/HEAD. Nessun submit di form.
- Non invia payload XSS reali — analisi statica della struttura dei form.
- Non segue redirect esterni (rimane sul dominio target).
- Se il sito è down → segnala e passa al target successivo.
