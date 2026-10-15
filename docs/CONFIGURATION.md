# Configuration

LabCA reads its settings from environment variables (and from a `.env` file in the working directory, for local development). Every setting below is a field of `app.config.Settings`; `tests/test_configuration_doc.py` fails if this table and the code disagree.

When `ENV=prod`, LabCA refuses to start if the configuration is unsafe. It lists every violation by setting name and never prints a value. The rules are in the "Prod checks" column.

## Core

| Setting | Default | Description | Prod checks |
|---|---|---|---|
| `APP_NAME` | `LabCA` | Display name in the UI and the OpenAPI title. | |
| `ENV` | `dev` | `dev`, `test`, or `prod`. `prod` turns on the startup checks in this table. | |
| `DATABASE_URL` | `sqlite:///./labca.db` | SQLAlchemy URL. LabCA is built and tested on SQLite only. | Must be a SQLite file under `/data`. |
| `SECRET_KEY` | `CHANGE_ME` | Signs the CSRF tokens. Generate at least 32 random characters. | Must not be `CHANGE_ME`; at least 32 characters. |
| `API_TOKEN_CREATION_SECRET` | unset | Shared secret required to create API tokens through the UI and API. Unset disables token creation. | |
| `LOG_LEVEL` | `INFO` | Python logging level. | |
| `LOG_FORMAT` | `text` | `text` for local use, `json` for one JSON object per line (cluster logging). Secrets and sealed key values are redacted in both formats. | |
| `ENABLE_API_DOCS` | `true` | Serves `/docs`, `/redoc`, and `/openapi.json`. When false, the three routes return 404 in every environment. | Must be false. |

## Key management

KEKs (key encryption keys) wrap the per-record data keys that encrypt every stored private key: each key is encrypted with AES-256-GCM under its own data key, and the data key is wrapped with the KEK using AES Key Wrap (RFC 3394).

| Setting | Default | Description | Prod checks |
|---|---|---|---|
| `LABCA_KEK_DIR` | unset | Directory of KEK files. Each file name is a KEK id (`[a-z0-9-]{1,32}`) and its content is the base64 encoding of 32 random bytes. Names starting with `.` are ignored, so a Kubernetes Secret volume works as is. | The keyring must load and must not be empty. |
| `LABCA_ACTIVE_KEK_ID` | unset | KEK id used for new encryptions. Older KEKs stay loaded for decryption until `python -m app.cli kek rewrap --to <id>` has moved every record. | Must name a loaded KEK. |

Outside prod, a KEK may also come from an environment variable `LABCA_KEK_<ID>=<base64 of 32 bytes>` (for example `LABCA_KEK_DEV_1` for id `dev-1`). Prod rejects KEKs from environment variables. These variables are not `Settings` fields, so they are not in the table.

## Public PKI and CRLs

| Setting | Default | Description | Prod checks |
|---|---|---|---|
| `PUBLIC_BASE_URL` | unset | Origin used for absolute URLs in `/pki/index.json` and in the CRL Distribution Point and Authority Information Access extensions of issued certificates, for example `https://labca.example.com`. No path, query, or fragment. Unset means path-only URLs and no extensions that need an origin. | Must be set and use `https://`. |
| `CRL_VALIDITY_HOURS` | `24` | `nextUpdate` minus `thisUpdate` of every CRL LabCA signs (1 to 720). A CRL is regenerated after a revocation and when half of this period has passed. | |
| `CRL_RETENTION_AFTER_EXPIRY_HOURS` | `1` | How long an expired revoked certificate stays on the CRL (0 to 8760). `cli prune` never deletes a certificate earlier than this. | |
| `PKI_STATIC_DIR` | unset | Directory holding `root-ca.pem` and `root-crl.der` from the offline ceremony, served at `/pki/root/ca.pem` and `/pki/root/crl.der`. Files larger than 1 MiB are not served. | |

## Workload identity

| Setting | Default | Description | Prod checks |
|---|---|---|---|
| `WORKLOAD_ISSUANCE_ENABLED` | `false` | Enables `POST /api/v1/workload/sign` and `/api/v1/workload/revoke`. When false both return 503. | |
| `WORKLOAD_TRUST_DOMAIN` | unset | SPIFFE trust domain, for example `labca.example.com`. Workload certificates carry `spiffe://<domain>/ns/<namespace>/sa/<serviceaccount>`. | Required when workload issuance is enabled. |
| `WORKLOAD_ISSUER_CA_NAME` | unset | Name of the CA that signs workload certificates (also the CA behind `/pki/issuing/*`). The general issuance API and UI refuse to issue from it. | Required when workload issuance is enabled. |
| `WORKLOAD_TOKEN_AUDIENCE` | `labca` | Audience a projected ServiceAccount token must carry. LabCA checks it with the Kubernetes TokenReview API. | |
| `WORKLOAD_ALLOWLIST` | empty | Comma-separated `<namespace>/<serviceaccount>` entries allowed to request certificates. Anything else gets 403 `not_allowlisted`. | |
| `WORKLOAD_CERT_TTL_MINUTES` | `60` | Lifetime of workload certificates (5 to 1440). | |
| `WORKLOAD_SIGN_RATE_PER_HOUR` | `30` | Sign requests allowed per SPIFFE ID per hour (token bucket, in process). Excess requests get 429 `rate_limited` with `retry_after_s`. | |
| `KUBE_SA_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | LabCA's own ServiceAccount token for TokenReview calls. Re-read on every call because kubelet rotates it. | |
| `KUBE_CA_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` | CA bundle used to verify the Kubernetes API server. | |

## Admin access

The admin UI and token UI are everything except `/health`, `/ready`, `/pki/*`, `/static/*`, and `/api/v1/*`. `/api/v1/*` uses API tokens or workload tokens instead.

| Setting | Default | Description | Prod checks |
|---|---|---|---|
| `ADMIN_AUTH_MODE` | `none` | `none` (no check, local development only), `localhost_only` (only loopback clients with no forwarding headers, for example through `kubectl port-forward`), or `cloudflare_access` (a valid Cloudflare Access JWT for an email in `ADMIN_EMAILS`). | Must not be `none`. |
| `CF_ACCESS_TEAM_DOMAIN` | unset | Cloudflare Zero Trust team domain, `<team>.cloudflareaccess.com`. The Access JWT issuer and JWKS URL derive from it. | Required in `cloudflare_access` mode. |
| `CF_ACCESS_AUD` | unset | Application audience tag of the Access application. Tokens for other applications are rejected. | Required in `cloudflare_access` mode. |
| `ADMIN_EMAILS` | empty | Comma-separated email addresses allowed in `cloudflare_access` mode, compared case-insensitively. Cloudflare Access enforces the same list at the edge; LabCA checks it again. | Required in `cloudflare_access` mode. |
| `ADMIN_BREAK_GLASS_LOCALHOST` | `false` | In `cloudflare_access` mode, also allow loopback clients with no forwarding headers (for recovery through `kubectl port-forward` when Access is unavailable). | |

## Container entrypoint variables

`docker-entrypoint.sh` reads these. They are not `Settings` fields.

- `PORT` (default `8000`): listen port for `serve`.
- `FORWARDED_ALLOW_IPS` (default `127.0.0.1`): proxies whose `X-Forwarded-*` headers uvicorn trusts. In the cluster this is the pod network of the ingress controller. `*` is rejected because it would let any client choose its own address.
- `UVICORN_LOG_LEVEL` (default `info`): uvicorn's own log level.

## Examples

Local development with Docker Compose sets `ENV=dev`, `ADMIN_AUTH_MODE=none`, a SQLite file under `/data`, and a throwaway KEK created by `scripts/dev-kek.sh`. The admin port is bound to `127.0.0.1` only.

The cluster deployment (`deploy/kustomize/base/labca/`) sets `ENV=prod`, `LOG_FORMAT=json`, `ENABLE_API_DOCS=false`, KEKs from the `labca-kek` Secret volume, and `SECRET_KEY`, `API_TOKEN_CREATION_SECRET`, and `CF_ACCESS_AUD` from the `labca-app` Secret. Everything else comes from the `labca-config` ConfigMap.
