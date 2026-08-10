# Slink plain Kubernetes manifests

Kustomize-based deployment for clusters that do not use Helm. The bundle runs
one API/scheduler replica, one unprivileged static frontend, PostgreSQL 16,
persistent archive storage, ClusterIP services, and TLS ingress. The API
entrypoint applies migrations before the server accepts traffic.

## Prepare and inspect

```bash
cp deploy/k8s/secret.env.example deploy/k8s/secret.env
chmod 600 deploy/k8s/secret.env
${EDITOR:-vi} deploy/k8s/secret.env

# Set the ingress host, TLS issuer, direct ingress-controller CIDR, and release
# image tags in the tracked manifests before rendering.
kubectl kustomize deploy/k8s >/tmp/slink-rendered.yaml
kubectl diff -k deploy/k8s
kubectl apply -k deploy/k8s
```

`secret.env` is ignored by Git and required at render time. Replace every
placeholder. `APP_ENV=production` then rejects weak JWT, administrator, database,
cookie, or base-URL configuration at startup.

The checked-in application images use a version tag as a readable baseline.
For stronger release identity, layer an environment-specific Kustomization that
sets the verified registry digest produced by the release workflow.

## First login and additional users

The administrator in `secret.env` is seeded on first startup. Add another user
with an interactive password prompt:

```bash
kubectl -n slink exec -it deployment/slink-api -- \
  python -m app.utils.create_user analyst viewer
```

No password is placed in process arguments.

## Upgrades

Change the image identity and apply the bundle. The API entrypoint serially
applies pending migrations before starting the new server process:

```bash
kubectl apply -k deploy/k8s
kubectl -n slink rollout status deployment/slink-api
kubectl -n slink rollout status deployment/slink-frontend
```

## External PostgreSQL

Remove the PostgreSQL StatefulSet and Service from `kustomization.yaml`, then
point `DATABASE_URL` in `secret.env` at a TLS-protected managed PostgreSQL 16
instance using the `postgresql+asyncpg://` driver.

## Operational requirements

- Verify a default StorageClass exists before relying on the bundled database
  and archive PersistentVolumeClaims.
- Set `TRUSTED_PROXY_CIDRS` only to the direct ingress-controller source address
  or narrow subnet. Empty ignores forwarding headers and is the safe default.
- Keep `/metrics`, the API service, and PostgreSQL private to the cluster.
- Back up to client-encrypted `.sql.gz.age` files and exercise restoration.
- Never commit `secret.env`, rendered Secret manifests, TLS private keys, or dumps.
