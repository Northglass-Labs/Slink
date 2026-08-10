# Slink deployment guide

Slink is a single-tenant, self-hosted service. The supported production shapes
are Docker Compose on one host, Helm with an existing Secret and immutable image
digests, or plain Kubernetes manifests through Kustomize.

## Production invariants

Every production deployment must provide:

- `APP_ENV=production`;
- a random `SECRET_KEY` of at least 32 bytes;
- a non-placeholder administrator password of 12–72 UTF-8 bytes;
- a strong database credential embedded in `DATABASE_URL`;
- `SECURE_COOKIES=true` and a non-local HTTPS `SLINK_BASE_URL`; and
- an exact direct-proxy address or narrow CIDR in `TRUSTED_PROXY_CIDRS` when
  forwarding headers are needed.

Startup fails if these invariants are not met. Keep the API, PostgreSQL, and
`/metrics` private, and expose only TLS ingress.

Run one API replica. Collection scheduling is currently in-process and does not
elect a leader across replicas; horizontally scaling the API would duplicate
polls until scheduler leadership is externalized.

## Docker Compose

The base file is a loopback-only development stack. The production overlay
removes the database, API, and frontend host ports; separates the database onto
an internal network; trusts only the fixed nginx address; and publishes nginx on
TCP 443.

```bash
cp .env.example .env
chmod 600 .env
${EDITOR:-vi} .env

# Set APP_ENV=production, strong credentials, SECURE_COOKIES=true, and the
# external HTTPS SLINK_BASE_URL. Install cert.pem/key.pem under nginx/certs/;
# keep the key owner-only while making it readable by container UID 101.
docker compose -f docker-compose.yml -f docker-compose.prod.yml config >/dev/null
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The API entrypoint applies migrations before starting. `setup.sh` is for the
loopback development stack; it performs authenticated smoke checks without
reading `.env` credentials into shell variables or command arguments.

Create additional users interactively:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec api \
  python -m app.utils.create_user analyst viewer
```

The command prompts twice for the password.

## Helm

The chart requires an out-of-band application Secret and immutable `sha256:`
digests for both images. If the bundled PostgreSQL subchart is enabled, its own
existing Secret is also required. No chart template renders credential values.

See [`deploy/helm/slink/README.md`](../deploy/helm/slink/README.md) for the
owner-only Secret-file workflow, managed/bundled database examples, and upgrade
contract.

## Kustomize

Copy `deploy/k8s/secret.env.example` to the ignored `deploy/k8s/secret.env`, set
mode 0600, replace every placeholder, configure TLS/hostname/proxy CIDR, and
inspect the render before applying:

```bash
kubectl kustomize deploy/k8s >/tmp/slink-rendered.yaml
kubectl diff -k deploy/k8s
kubectl apply -k deploy/k8s
```

The checked-in Secret example is never consumed. Rendering deliberately fails
while the ignored local Secret file is absent. See
[`deploy/k8s/README.md`](../deploy/k8s/README.md) for upgrades and external
PostgreSQL.

## Client-encrypted backups

`scripts/backup.sh` creates owner-only `.sql.gz.age` files and encrypts before
the final filename or optional S3 upload exists. It never accepts a database URL
argument. S3 objects remain client-encrypted and also request server-side
encryption.

For the production Compose database, run `pg_dump` inside the private database
container:

```bash
export SLINK_COMPOSE_DATABASE=1
export PGUSER=slink
export PGDATABASE=slink
export BACKUP_AGE_RECIPIENT='age1REPLACE_WITH_PUBLIC_RECIPIENT'
./scripts/backup.sh
```

For a directly reachable managed database, set `PGHOST`, `PGPORT`, `PGUSER`,
`PGDATABASE`, and either `PGPASSWORD` from a credential store or `PGPASSFILE`
pointing to a mode-0400/0600 file. Do not put credentials in cron command text.

Local retention defaults to 30 days. Set `AWS_S3_BUCKET` for encrypted off-host
copies and optionally select KMS-backed S3 encryption with `AWS_S3_SSE=aws:kms`
and `AWS_KMS_KEY_ID`.

Restore requires the encrypted file, a mode-0400/0600 age identity, two explicit
safety switches, and typing the target database name:

```bash
export SLINK_COMPOSE_DATABASE=1
export PGUSER=slink
export PGDATABASE=slink
export BACKUP_AGE_IDENTITY_FILE="$HOME/.config/slink/backup-age-key.txt"
SLINK_RESTORE_OK=1 ./scripts/restore.sh --yes backups/slink-TIMESTAMP.sql.gz.age
```

The restore decrypts as a stream; plaintext SQL is never written to disk. Test
restoration against an isolated non-production database on a regular schedule.

## Observability

Prometheus metrics are exposed by the API at `/metrics`. Compose nginx blocks
that path from public ingress; scrape the API over its private network. In
Kubernetes, scrape the API ClusterIP rather than the Ingress. The example Grafana
dashboard is documented in [`docs/grafana/README.md`](grafana/README.md).

## Go-live checklist

- [ ] Production startup validation succeeds with no placeholders.
- [ ] TLS and Secure cookies are active.
- [ ] Only the intended TLS ingress is publicly reachable.
- [ ] Forwarding headers are trusted only from the direct proxy.
- [ ] Application/provider/database credentials live outside Git and Helm values.
- [ ] Release images are selected by verified digest where supported.
- [ ] `/metrics` is private.
- [ ] An encrypted backup and isolated restore have both been verified.
