# LabCA Demo Checklist

1. **Startup**
   - `cp .env.example .env` and set secrets.
   - Run `uvicorn app.main:app --reload` or `docker compose up`.
   - Visit `http://localhost:8000/health` and `/`.

2. **Initial CA setup**
   - Open `/setup`.
   - Create a new root CA.
   - Confirm it appears on `/cas`.

3. **Issue a certificate from CA**
   - Go to `/cas/{ca_id}/issue`.
   - Issue a server TLS cert for `example.local`.
   - Download PEMs and verify on `/certificates`.

4. **Quick Certificate**
   - Use `/quick-cert` (simple mode).
   - Generate and view output.

5. **Profiles**
   - Create a “Server TLS” profile (`/profiles/new`).
   - Use it from a CA issue page and confirm defaults.

6. **Revocation**
   - Revoke one certificate from `/certificates/{id}`.
   - Confirm status updates to Revoked.

7. **API**
   - Visit `/api`.
   - Create a token and copy the value.
   - Issue a cert via `curl` against `/api/v1/certificates`.

8. **Notifications & Audit**
   - Open `/notifications` to confirm rules.
   - Visit `/audit` and verify the previous actions are logged.

9. **Smoke test routes**
   - `/`, `/quick-cert`, `/help`, `/cas`, `/certificates`, `/profiles`, `/settings`, `/notifications`, `/audit`, `/api`.

Document any issues spotted during the walkthrough and fix before demoing.
