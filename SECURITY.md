# Security policy

## Supported versions

Slink is beta software. Security fixes are made on the latest release line and
the `main` branch. Upgrade to the newest published patch before reporting a
problem that may already be fixed.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Send a concise
report to [hello@northglass.io](mailto:hello@northglass.io) with the affected
version, impact, reproduction steps, and any suggested mitigation. Remove live
credentials, personal data, and third-party confidential data from evidence.

We will acknowledge receipt, validate the report, coordinate remediation, and
credit reporters who want attribution. Do not test against systems or data you
do not own or have explicit permission to assess.

## Deployment assumptions

Slink is a single-tenant, self-hosted application. Production deployments must:

- set `APP_ENV=production` and satisfy the startup security checks;
- terminate TLS before Slink and use Secure cookies;
- expose only the intended TLS ingress, keeping PostgreSQL, the API, and
  `/metrics` on private networks;
- trust forwarding headers only from the direct reverse proxy;
- store credentials in a secret manager or owner-only files outside Git; and
- encrypt backups client-side and test restoration regularly.

The browser access token is stored in `localStorage`; the rotating refresh token
is in an httpOnly Secure cookie. This is an explicit single-tenant trade-off.
Do not expose Slink as a public multi-tenant service without redesigning browser
token storage, tenancy boundaries, authorization, and scheduler isolation.
