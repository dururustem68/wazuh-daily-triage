# Kubernetes and Helm: production guide

**For:** platform engineers who run the application in a cluster. For a first look use `port-forward`; this page
is about a deployment other people will rely on. Chart reference:
[Helm chart README](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/helm/wazuh-daily-triage/README.md);
Kustomize: [deploy/kubernetes/README.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/kubernetes/README.md).

## What gets deployed

One Deployment with **one replica** (strategy `Recreate`), a Service on port 8080, a Secret, a ConfigMap with
`environments.yaml`, and optionally an Ingress, a NetworkPolicy and a read-only ClusterRole. The pod runs as
non-root (uid 10001) with a read-only root filesystem and all capabilities dropped. There is no
PersistentVolumeClaim: reports and the knowledge base are documents in your Wazuh Indexer.

| Probe | Path | Meaning |
|---|---|---|
| liveness | `/healthz` | the process answers; no dependency is touched |
| readiness | `/readyz` | startup and configuration are done; no network call |

Neither probe calls Wazuh on purpose. If readiness failed during a SIEM outage, Kubernetes would remove the one
page that explains the outage.

## Install with Helm

```sh
helm repo add wazuh-daily-triage https://dururustem68.github.io/wazuh-daily-triage
helm repo update
helm install wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --namespace wazuh-daily-triage --create-namespace \
  --version 0.3.0 -f my-values.yaml
```

Chart 0.3.0 deploys application 0.11.0. The values that matter in production:

| Value | Set it to |
|---|---|
| `secret.*` | every key becomes an environment variable: `APP_PASSWORD`, `APP_SECRET`, `LLM_API_KEY`, `INDEXER_PASSWORD`, `API_PASSWORD`, and when used `VIEWER_PASSWORD`, `MCP_TOKEN`, `METRICS_TOKEN` |
| `env.*` | non-secret switches such as `ENVIRONMENT: production`, `AUTH_DISABLED`, `ADMIN_ENVS`, `LOG_LEVEL` |
| `config.environments` | a complete `environments.yaml`; secrets as `${VAR}` placeholders |
| `app.cookieSecure` | `true` behind TLS |
| `app.forwardedAllowIPs` | the ingress controller's pod CIDR; never `*` |
| `app.notifyUiUrl` | the public URL, used as the link in notifications |
| `ingress.enabled`, `ingress.className`, `ingress.hosts`, `ingress.tls` | your ingress |
| `networkPolicy.ingressNamespace` | the namespace of **your** ingress controller |
| `networkPolicy.wazuhNamespace` / `networkPolicy.wazuhCIDR` | where the Indexer and API are: a namespace in the cluster, or an address outside it |
| `rbac.create`, `rbac.namespaces` | the read-only ClusterRole for the Kubernetes tools; `false` if you do not use them |

Prefer an existing secret mechanism (External Secrets, Sealed Secrets, SOPS) over passwords in a values file in
git.

## Install with Kustomize

Copy the example overlay, point it at a pinned remote base, and add the components you need
(`networkpolicy`, `ingress-nginx`, `ingress-traefik-authentik`, `rbac-readonly`). The commands are in
[Installation](Installation), section B2. After a change to `secret.env`, `kubectl apply -k .` creates a Secret
with a new name and the pod restarts with it.

## Verify

```sh
kubectl -n wazuh-daily-triage rollout status deploy/wazuh-daily-triage
kubectl -n wazuh-daily-triage logs deploy/wazuh-daily-triage | head -50
kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage -- python -m app.check
kubectl -n wazuh-daily-triage port-forward svc/wazuh-daily-triage 8080:8080
```

**Expected:** the rollout completes, the log lists the configured environments and the schedule without a
security warning, and every connection check passes. Then follow [Getting started](Getting-Started) from step 7.

## Network policy

On by default in the chart since 0.10. The policy selects every pod in the release namespace, so install the
application into a namespace of its own. Inbound: only the ingress controller's namespace may reach the pod.
Outbound: DNS, the Wazuh Indexer (9200) and API (55000), HTTPS (443) for the model and webhooks, SMTP (587, 465).

Add egress yourself for:

- Prometheus and Loki, if configured as sources;
- the Kubernetes API (usually 6443 on the control-plane nodes), if the Kubernetes tools are on;
- a model served inside the cluster on another port (Ollama: 11434);
- an S3 endpoint on a port other than 443.

A blocked egress shows up as a timeout in `python -m app.check`, not as a refused connection.

## Ingress and SSO

| Setup | Settings |
|---|---|
| Application password behind TLS | `app.cookieSecure: true`, `app.forwardedAllowIPs` |
| SSO proxy in front (oauth2-proxy with Keycloak, Authentik forward auth) | `AUTH_DISABLED=true`, the proxy forwards a user and a group header, `SSO_ADMIN_GROUPS` (and `SSO_VIEWER_GROUPS`), and `TRUSTED_PROXIES` or `PROXY_SECRET` |

With `AUTH_DISABLED=true` the NetworkPolicy is not optional: without it anything inside the cluster can reach
the UI without signing in. Since 0.10, requests without a user header are answered with `401`. Worked examples:
[SSO proxy authentication](SSO-Proxy-Auth). The `/mcp` endpoint authenticates with its own bearer token and is
usually routed around the SSO login.

## One replica

The scheduler runs inside the process. Two replicas would run every check twice and send every notification
twice. Keep `replicaCount: 1`. If you need more pods for availability of the UI, set `WDT_SCHEDULER=false` on
the additional ones.

## The audit trail on Kubernetes

The audit trail is a file under `/app/logs`, by default on an `emptyDir`. It disappears with the pod. For
anything you must keep, either ship it with a log agent or sidecar, or mount a PersistentVolumeClaim there. With
`ENVIRONMENT=production`, a log directory that is not writable makes state-changing requests fail with `503`
rather than proceed unaudited.

## Same cluster as Wazuh, or not

- **Same cluster:** use the service names (`https://indexer.wazuh.svc:9200`, `https://wazuh.wazuh.svc:55000`).
  The Indexer never has to be exposed.
- **Wazuh elsewhere:** the pods need a route to 9200 and 55000 through your internal network or VPN, and
  `networkPolicy.wazuhCIDR`. Never expose the Indexer to the Internet for this.
- On wazuh-kubernetes the Indexer users are usually defined in `internal_users.yml`; a user created only through
  the REST API can be overwritten by `securityadmin`.

## Upgrade and rollback

```sh
helm upgrade wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --namespace wazuh-daily-triage --version <chart version> -f my-values.yaml
helm -n wazuh-daily-triage rollback wazuh-daily-triage <revision>
```

Take a backup first and read the version notes: [Upgrade](Upgrade).

*Applies to 0.11.0, chart 0.3.0 · reviewed 2026-11-11*

---

[English](Kubernetes) · [Türkçe](Kubernetes-TR)
