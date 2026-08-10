# Slink Helm chart

Production-oriented Helm packaging for Slink. The chart requires immutable API
and frontend image digests and an existing Kubernetes Secret; it never renders
credentials from values.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- published Slink API and frontend image digests
- an ingress controller when `ingress.enabled=true`
- PostgreSQL 16, either managed externally or through the optional subchart
- a default StorageClass, an existing archive claim, or archive persistence
  explicitly disabled for intentionally ephemeral environments

## Prepare secrets

Create the application Secret from an owner-only file so credentials do not
appear in shell arguments or Helm release state:

```bash
umask 077
install -m 600 /dev/null /tmp/slink-secret.env
${EDITOR:-vi} /tmp/slink-secret.env
# Add DATABASE_URL, SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD and any optional
# provider credentials, one KEY=value per line.

kubectl create namespace slink
kubectl -n slink create secret generic slink-secrets \
  --from-env-file=/tmp/slink-secret.env
rm -f /tmp/slink-secret.env
```

For the bundled Bitnami PostgreSQL chart, create a second owner-only file with
both `postgres-password` and `password` set to the same strong database
credential, then create `slink-postgresql-credentials` from that file. Point the
application `DATABASE_URL` at `slink-postgresql:5432` using that credential.

## Install with managed PostgreSQL

```bash
helm dependency build ./deploy/helm/slink
helm install slink ./deploy/helm/slink \
  --namespace slink \
  --set existingSecret=slink-secrets \
  --set postgresql.enabled=false \
  --set api.image.digest=sha256:REPLACE_WITH_API_DIGEST \
  --set frontend.image.digest=sha256:REPLACE_WITH_FRONTEND_DIGEST \
  --set ingress.enabled=true \
  --set 'ingress.hosts[0].host=slink.example.com'
```

## Install with bundled PostgreSQL

Resolve the pinned subchart dependency, create both Secrets as described above,
then install with:

```bash
helm dependency build ./deploy/helm/slink
helm install slink ./deploy/helm/slink \
  --namespace slink \
  --set existingSecret=slink-secrets \
  --set postgresql.auth.existingSecret=slink-postgresql-credentials \
  --set api.image.digest=sha256:REPLACE_WITH_API_DIGEST \
  --set frontend.image.digest=sha256:REPLACE_WITH_FRONTEND_DIGEST
```

The migration hook applies `alembic upgrade head` before install and upgrade.
Once the API is healthy, additional users can be created without putting their
password in process arguments:

```bash
kubectl -n slink exec -it deployment/slink-api -- \
  python -m app.utils.create_user analyst viewer
```

The command prompts twice for the password.

## Important values

| Path | Default | Notes |
|---|---|---|
| `api.replicas` | `1` | Keep one scheduler-bearing API replica unless scheduler leadership is externalized. |
| `api.image.digest` | `""` | Required immutable `sha256:` digest. |
| `frontend.image.digest` | `""` | Required immutable `sha256:` digest. |
| `api.archive.persistence.enabled` | `true` | Persist pruned JSONL archives instead of losing them on pod replacement. |
| `api.archive.persistence.existingClaim` | `""` | Optional pre-provisioned archive claim. |
| `existingSecret` | `""` | Required application Secret. |
| `config.appEnv` | `production` | Enables fail-closed production validation. |
| `config.trustedProxyCidrs` | `""` | Set only to the direct ingress-controller source address/CIDR. |
| `postgresql.enabled` | `true` | Disable for a managed external database. |
| `postgresql.auth.existingSecret` | `""` | Required when bundled PostgreSQL is enabled. |

See [`values.yaml`](./values.yaml) for the full schema.

## Upgrade and uninstall

Provide the new immutable digests on every upgrade; do not rely on mutable tags
or `--reuse-values` for release identity.

```bash
helm upgrade slink ./deploy/helm/slink \
  --namespace slink \
  --set existingSecret=slink-secrets \
  --set postgresql.enabled=false \
  --set api.image.digest=sha256:REPLACE_WITH_NEW_API_DIGEST \
  --set frontend.image.digest=sha256:REPLACE_WITH_NEW_FRONTEND_DIGEST

helm uninstall slink --namespace slink
```

The chart-created archive claim is deliberately retained after uninstall. Back
up and verify the database and archive before deleting any PVC or changing
PostgreSQL major versions.
