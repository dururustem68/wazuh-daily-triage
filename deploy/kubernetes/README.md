# Kubernetes

> **Prefer Helm?** An equivalent chart ships at [../helm/wazuh-daily-triage](../helm/wazuh-daily-triage).

Kustomize manifests:

```
deploy/kubernetes/
├── base/                         Deployment (1 replica, hardened), Service
├── components/                   optional building blocks for an overlay
│   ├── networkpolicy/            only the ingress controller may reach the pod; DNS, Wazuh, HTTPS, SMTP out
│   ├── ingress-nginx/            ingress-nginx + TLS (cert-manager), app password login, oauth2-proxy option
│   ├── ingress-traefik-authentik/ Traefik IngressRoute + Authentik forward auth (SSO, AUTH_DISABLED=true)
│   └── rbac-readonly/            service account + read-only ClusterRole for the Kubernetes tools (docs/sources.md)
└── example/                      an overlay: namespace, environments.yaml, context, seed, secret.env
```

```sh
cp -r deploy/kubernetes/example ~/triage-overlay && cd ~/triage-overlay
# point the base at the repository:
sed -i 's#  - ../base .*#  - https://github.com/dururustem68/wazuh-daily-triage//deploy/kubernetes/base?ref=v0.6.4#' kustomization.yaml
cp secret.env.example secret.env && vi secret.env environments.yaml context.md
kubectl apply -k .
kubectl -n wazuh-daily-triage rollout status deploy/wazuh-daily-triage
kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage -- python -m app.check
kubectl -n wazuh-daily-triage port-forward svc/wazuh-daily-triage 8080:8080   # http://127.0.0.1:8080
```

## Components

Enable them in your overlay's `kustomization.yaml` (`components:`). They contain example host names
(`triage.example.com`), namespaces and addresses — copy the component directory next to your overlay and edit it:

| Component | Adds | Also sets |
|---|---|---|
| `networkpolicy` | NetworkPolicy: ingress only from the controller namespace; egress DNS, Wazuh 9200/55000, 443, 587/465 | — |
| `ingress-nginx` | Ingress (class `nginx`, TLS secret `triage-tls`, `cert-manager.io/cluster-issuer`) | `COOKIE_SECURE=true`, `FORWARDED_ALLOW_IPS` |
| `ingress-traefik-authentik` | Traefik `Middleware` (forwardAuth) + `IngressRoute`, Authentik outpost route, `/mcp` route | `AUTH_DISABLED=true`, `COOKIE_SECURE=true`, `NOTIFY_UI_URL` |
| `rbac-readonly` | ServiceAccount, ClusterRole (`get`/`list` pods, pods/log, nodes, events, workloads, jobs, services, ingresses, PVCs — no secrets) | mounts the token into the pod |

With `networkpolicy` and `sources:` enabled, add egress for Prometheus / Loki ports and the Kubernetes API
(usually 6443 on the control-plane nodes).

With SSO in front (`AUTH_DISABLED=true`) always add `networkpolicy` as well — otherwise anything inside the
cluster can reach the UI without logging in. The SSO user name (`X-authentik-username`, `X-Forwarded-User`,
`Remote-User`, `X-Auth-Request-User`) is recorded on rule deployments.

Notifications, rule deployment and the LLM need no extra objects: set them in `environments.yaml` and the
secrets in `secret.env` (see the example). After changing `secret.env` run `kubectl apply -k .` again — the
generated Secret gets a new name and the pod restarts with it.

## Notes

- **One replica only.** The scheduler runs inside the process; more replicas would run each check more than
  once. The Deployment uses the `Recreate` strategy for the same reason.
- **Stateless.** Reports and the knowledge base live in the Wazuh Indexer (`daily-triage-*`); no PVC is needed.
- **Hardened by default:** non-root, read-only root filesystem, all capabilities dropped, no service account
  token, `restricted` Pod Security level.
- **Same cluster as Wazuh?** Use the in-cluster service names (example above) — the indexer never has to be
  exposed. Otherwise make sure pods can reach the indexer (9200) and API (55000).
- **Exposing the UI:** start with `port-forward`. For an Ingress, put SSO (oauth2-proxy, Authentik, Keycloak
  forward-auth) in front and set `AUTH_DISABLED=true`, or keep the app password and set `COOKIE_SECURE=true`
  behind TLS. Set `FORWARDED_ALLOW_IPS` to your ingress controller's pod CIDR, never `*`.
- **Knowledge import:** `kubectl -n wazuh-daily-triage exec -i deploy/wazuh-daily-triage -- python -m app.kb import - --update < notes.yaml`
