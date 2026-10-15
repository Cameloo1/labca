# mtls-demo

One Go binary, standard library only, with three subcommands that show short-lived workload identity from LabCA:

- `server`: obtains a 1-hour X.509 certificate from LabCA using a projected ServiceAccount token, serves mTLS on `MTLS_ADDR`, authorizes peers by SPIFFE ID, enforces the signed CRL (fail closed), and serves a public status page and `/status.json` on `STATUS_ADDR`.
- `client`: obtains its own certificate, calls the server every `INTERVAL`, and accepts only the server SPIFFE ID in `EXPECTED_SERVER_ID`.
- `verifier`: run as a CronJob. Proves that a valid identity passes and that forged, untrusted, revoked and unauthorized identities fail, then writes the results to a ConfigMap.

Private keys exist only in memory. The token file is re-read on every LabCA call because kubelet rotates it. Certificates renew between 40 and 60 percent of their lifetime.

Any other first argument prints usage to stderr and exits 2.

## Environment

Shared by all subcommands:

| Variable | Default | Notes |
|---|---|---|
| `LOG_LEVEL` | `info` | slog JSON on stdout |
| `LABCA_URL` | `http://labca.labca-system.svc.cluster.local:8000` | LabCA base URL |
| `TOKEN_FILE` | `/var/run/secrets/labca/token` | projected token, audience `labca` |
| `TRUST_BUNDLE_FILE` | `/etc/labca/trust/trust-bundle.pem` | PEM roots, reloaded when the content changes |

`server`:

| Variable | Default | Notes |
|---|---|---|
| `ALLOWED_CLIENT_IDS` | required | comma-separated SPIFFE IDs |
| `CRL_URL` | `$LABCA_URL/pki/issuing/crl.der` | |
| `CRL_REFRESH` | `30s` | |
| `STATUS_DIR` | `/etc/mtls-status` | holds `results.json` from the verifier |
| `MTLS_ADDR` | `:8443` | |
| `STATUS_ADDR` | `:8080` | plain HTTP |

`client`:

| Variable | Default | Notes |
|---|---|---|
| `SERVER_URL` | `https://demo-server.mtls-demo.svc.cluster.local:8443/v1/ping` | |
| `EXPECTED_SERVER_ID` | required | |
| `INTERVAL` | `15s` | |
| `HEALTH_ADDR` | `:8081` | `/healthz` |

`verifier`:

| Variable | Default | Notes |
|---|---|---|
| `SERVER_URL` | as client | |
| `SERVER_STATUS_URL` | `http://demo-server.mtls-demo.svc.cluster.local:8080/status.json` | |
| `DEMO_CLIENT_ID` | required | |
| `EXPECTED_SERVER_ID` | required | |
| `AUTHORIZED_CALL_MAX_AGE` | `120s` | |
| `REVOKE_WAIT_TIMEOUT` | `120s` | |
| `REVOKE_POLL_INTERVAL` | `2s` | |
| `KUBE_API_URL` | `https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT` | |
| `KUBE_TOKEN_FILE` | `/var/run/secrets/kube-api/token` | |
| `KUBE_CA_FILE` | `/var/run/secrets/kube-api/ca.crt` | |
| `POD_NAMESPACE` | required | |
| `STATUS_CONFIGMAP` | `mtls-status` | |

## Development

Run from this directory: `go vet ./... && go test -race ./...`.
