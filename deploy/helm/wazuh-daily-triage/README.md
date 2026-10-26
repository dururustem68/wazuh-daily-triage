# Wazuh Daily Triage — Helm chart

Deploy the [wazuh-daily-triage](https://github.com/dururustem68/wazuh-daily-triage) container to Kubernetes.
Same hardened deployment as the [kustomize manifests](../kubernetes/README.md): single replica, non-root,
read-only filesystem, no PVC, optional read-only RBAC for the Kubernetes tools.

## Install

```sh
# 1. Create a values override file with your secrets and configuration.
#    Start from values.yaml (it documents every knob and ships a full example).
cat > my-values.yaml <<'EOF'
secret:
  APP_PASSWORD: "..."
  APP_SECRET: "$(openssl rand -hex 32)"
  LLM_API_KEY: "..."
  INDEXER_PASSWORD: "..."
  API_PASSWORD: "..."
EOF

# 2. Install
helm repo add wazuh-daily-triage https://dururustem68.github.io/wazuh-daily-triage   # once published
helm install wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage -f my-values.yaml

# …or install straight from the repository:
helm install wazuh-daily-triage ./deploy/helm/wazuh-daily-triage -f my-values.yaml
```

## What you must configure

Everything secret lives under `secret:` (a Kubernetes `Secret`); the application reads it through `${VAR}`
placeholders inside `config.environments`:

| Key | What |
|---|---|
| `secret.APP_PASSWORD` | the web UI password (or use SSO + `AUTH_DISABLED=true`) |
| `secret.APP_SECRET` | session signing key (`openssl rand -hex 32`) |
| `secret.LLM_API_KEY` | your AI provider key |
| `secret.INDEXER_PASSWORD`, `secret.API_PASSWORD` | Wazuh indexer / API credentials |
| `config.environments` | the `environments.yaml` — one block per Wazuh |

Non-secret process env (language, timezone, cookie, proxy) goes in `app.*` / `env:`.

## Optional blocks

| Value | Adds |
|---|---|
| `rbac.create: true` (default) | read-only `ClusterRole` (`get`/`list` pods, nodes, events, workloads, … — no secrets) so the optional Kubernetes tools work in-cluster. |
| `ingress.enabled: true` | an nginx `Ingress` with TLS. Put an SSO proxy in front and set `AUTH_DISABLED=true` for team use. |
| `networkPolicy.enabled: true` | egress to DNS, Wazuh (9200/55000), HTTPS and SMTP; ingress only from the controller namespace. |

## Verify

```sh
helm lint ./deploy/helm/wazuh-daily-triage
helm template wazuh-daily-triage ./deploy/helm/wazuh-daily-triage > /tmp/rendered.yaml
kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage -- python -m app.check
```

See [docs/](../docs/) and the [root README](../../README.md) for the full feature set.
