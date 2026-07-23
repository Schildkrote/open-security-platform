# ai-access-broker

An open **AI Access Broker for employees** — the control point between your
people and the AI SaaS apps they want to use. Provides SSO, an app catalog,
approval workflows, DLP/redaction on proxied traffic, data-residency controls,
and usage/spend tracking. Zero runtime dependencies (Node 22 stdlib + `node:sqlite`).

## Features (MVP)

- **AI app catalog** with risk rating, vendor, category, and data-residency tags
- **SSO via a built-in mock OIDC IdP** (authorization-code flow → signed JWT id_tokens)
- **Access requests + approval workflow** (auto-approve for low-risk apps)
- **Reverse-proxy DLP**: redacts PII/secrets from traffic to AI apps
- **Data-residency enforcement**: blocks apps whose residency isn't permitted
- **Usage & spend logging** per app (calls, redactions, estimated cost)

## Quickstart

```bash
npm run seed     # seed a sample app catalog into broker.db
DB_PATH=broker.db npm start   # listen on :8081
```

Flow:

```bash
# 1. Log in (mock IdP) -> get a token
CODE=$(curl -s localhost:8081/idp/login -d '{"email":"user@corp.com","role":"user"}' | jq -r .code)
TOKEN=$(curl -s localhost:8081/idp/token -d "{\"code\":\"$CODE\"}" | jq -r .id_token)

# 2. Request access to an app (list apps with GET /apps)
curl -s localhost:8081/access-requests -H "Authorization: Bearer $TOKEN" \
  -d '{"app_id":"<APP_ID>","justification":"need it"}'

# 3. An admin approves it (POST /access-requests/:id/decide {"approve":true})

# 4. Use the app through the broker (PII is redacted)
curl -s localhost:8081/proxy/<APP_ID> -H "Authorization: Bearer $TOKEN" \
  -d 'my email is jane@corp.com'
```

## Routes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/idp/login` | – | Start SSO, returns a code |
| POST | `/idp/token` | – | Exchange code for id_token |
| GET | `/apps` | – | List catalog |
| POST | `/apps` | admin | Register an app |
| POST | `/access-requests` | user | Request access |
| GET | `/access-requests` | – | List requests (`?status=`) |
| POST | `/access-requests/:id/decide` | admin | Approve/deny |
| POST | `/proxy/:appId` | user | Proxied, redacted app call |
| GET | `/usage` | admin | Spend/usage summary |

## Tests

```bash
npm test
```

## License

Apache-2.0
