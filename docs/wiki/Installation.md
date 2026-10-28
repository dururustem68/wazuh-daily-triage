# Installation

Three supported ways to run it. All of them use the same container image and the same configuration files;
pick one and continue with [Configuration](Configuration).

| Path | Use it when | Time |
|---|---|---|
| Docker Compose | a VM, an all-in-one Wazuh, or a first test | 5–15 min |
| Kubernetes (Helm or Kustomize) | you already run Wazuh in a cluster | 15–30 min |
| Local Python | development or a quick look at the code | 5 min |

## Before you start

1. **Wazuh access.** The Indexer (9200) is required; the Wazuh API (55000) is optional but enables agent,
   daemon, rule and logtest checks. Create the read-only accounts from
   [docs/permissions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md) — do not use admin credentials.
2. **A model.** An API key for Anthropic or any OpenAI-compatible endpoint, or a local model (Ollama, vLLM,
   LM Studio). `LLM_PROVIDER=mock` is only for demos.
3. **TLS.** The UI has a password and a signed cookie; expose it through HTTPS, never plain HTTP on a shared
   network.
4. **Network.** The container needs HTTPS to the Indexer and API, and to your model endpoint. For self-signed
   Wazuh certificates copy the CA to `./config/certs/` and use `ca_file`.

## Option A — Docker Compose

### A1. Demo (no Wazuh, no model)

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git
cd wazuh-daily-triage
cp .env.example .env
```

Edit `.env`:

```sh
WDT_DEMO=true
LLM_PROVIDER=mock
APP_PASSWORD=a-long-demo-password
```

```sh
docker compose up -d --build
```

Open <http://127.0.0.1:8080>, sign in, press **Run check now** once. The demo uses `config/demo.yaml` and
synthetic data; no Wazuh connection is attempted. `WDT_DEMO=true` must never be combined with
`ENVIRONMENT=production` — startup refuses it. Running the **pulled 0.7.0 image** instead of a local build? Also
set `WDT_CONFIG=config/demo.yaml` (fixed after 0.7.0).

### A2. A real Wazuh (single environment)

`docker-compose.yml` publishes the port on `127.0.0.1` only, mounts `./config` read-only and `./logs` for the
audit trail. Start from the example file:

```sh
cp .env.example .env
openssl rand -hex 32        # APP_SECRET
```

Minimal `.env`:

```sh
ENVIRONMENT=production
APP_PASSWORD=<strong unique password>
APP_SECRET=<output of openssl rand -hex 32>
COOKIE_SECURE=true
FORWARDED_ALLOW_IPS=172.16.0.0/12

LLM_PROVIDER=anthropic
LLM_MODEL=<model id>
LLM_API_KEY=<key>

WAZUH_ENV_NAME=Production
WAZUH_INDEXER_URL=https://wazuh-indexer.example.internal:9200
WAZUH_INDEXER_USER=daily-triage
WAZUH_INDEXER_PASSWORD=<indexer password>
WAZUH_API_URL=https://wazuh-manager.example.internal:55000
WAZUH_API_USER=daily-triage
WAZUH_API_PASSWORD=<api password>
WAZUH_CA_FILE=/app/config/certs/root-ca.pem
```

`FORWARDED_ALLOW_IPS` must be the address the **container** sees the proxy coming from. A proxy on the host that
connects to the published `127.0.0.1:8080` arrives from the Docker bridge gateway (for example `172.18.0.1`),
not from `127.0.0.1`; check it with `docker network inspect <project>_default` and narrow the range to it. If it
is wrong, forwarded headers are ignored: every user shares one IP in the login throttle and the audit log. Never
use `*`.

Copy the CA:

```sh
mkdir -p config/certs
cp /path/to/root-ca.pem config/certs/root-ca.pem
```

Then:

```sh
docker compose up -d
docker compose exec triage python -m app.check
```

`python -m app.check [env…] [--no-llm]` (or **Test connections** on the environment page) verifies the Indexer
(alerts, vulnerabilities, storage indices), the API, configured extra sources and the model without starting a
run. Notifications have their own **Test notification** button.

> Comments in `.env` must be on their own line: `docker compose` treats everything after `#` on a value line as
> part of the value.

> **Pin the image for production.** `docker-compose.yml` uses `:latest` so the demo always works. Replace it with
> `ghcr.io/dururustem68/wazuh-daily-triage:0.7.0` (or your own digest) so an upgrade is a deliberate change.

### A3. Several Wazuh environments

Create the YAML file and point the container at it (it already mounts `./config`):

```sh
cp config/environments.example.yaml config/environments.yaml
mkdir -p config/context config/seed
cp config/context/example.md config/context/prod.md
vi config/environments.yaml
```

With `config/environments.yaml` present, the `WAZUH_*` single-environment variables are ignored and every
environment comes from the YAML. Secrets stay in `.env` as `${VARS}` and are expanded at startup. See
[Configuration](Configuration#the-yaml-file) for the full schema.

### A4. A local model (no alert data leaves your network)

`docker-compose.yml` ships an optional Ollama profile:

```sh
docker compose --profile ollama up -d
docker exec -it ollama ollama pull qwen3:14b
```

```sh
# .env
LLM_PROVIDER=openai
LLM_BASE_URL=http://ollama:11434/v1
LLM_MODEL=qwen3:14b
```

Then restart `triage`. Report quality follows the model: small models tend to skip tool calls and produce
thinner findings, so try a larger one before tuning prompts. With a local model, alert content never leaves
the host — often the deciding argument in a regulated environment.

## Option B — Kubernetes

Both the Helm chart and the Kustomize base deploy the same hardened pod: one replica, non-root, read-only root
filesystem, no PVC (state lives in the Wazuh Indexer), `/healthz` liveness and `/readyz` readiness.

### B1. Helm

```sh
helm repo add wazuh-daily-triage https://dururustem68.github.io/wazuh-daily-triage
helm repo update
```

`my-values.yaml`:

```yaml
secret:
  APP_PASSWORD: "..."
  APP_SECRET: "..."            # openssl rand -hex 32
  LLM_API_KEY: "..."
  INDEXER_PASSWORD: "..."
  API_PASSWORD: "..."

app:
  cookieSecure: true
  forwardedAllowIPs: "10.0.0.0/8"   # the ingress controller's pod CIDR, never "*"
```

```sh
helm install wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --version 0.1.3 -f my-values.yaml
```

Or install straight from a checkout: `helm install wazuh-daily-triage ./deploy/helm/wazuh-daily-triage -f my-values.yaml`.

Every key under `secret:` becomes an environment variable in the pod, so `VIEWER_PASSWORD`, `MCP_TOKEN` and
`METRICS_TOKEN` go there too. Non-secret switches (`AUTH_DISABLED`, `LOG_LEVEL`, `ADMIN_ENVS`, …) go under
`env:`. The application configuration (`config.environments`) is a full `environments.yaml` with `${VAR}`
placeholders.

### B2. Kustomize

```sh
cp -r deploy/kubernetes/example ~/triage-overlay
cd ~/triage-overlay
# outside the repository the relative "../base" no longer resolves — point it at the pinned remote base:
sed -i 's#^  - ../base.*#  - https://github.com/dururustem68/wazuh-daily-triage//deploy/kubernetes/base?ref=v0.7.0#' kustomization.yaml
cp secret.env.example secret.env
vi secret.env environments.yaml context.md
kubectl apply -k .
kubectl -n wazuh-daily-triage rollout status deploy/wazuh-daily-triage
kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage -- python -m app.check
```

Optional components in `deploy/kubernetes/components/`: `networkpolicy`, `ingress-nginx`,
`ingress-traefik-authentik` and `rbac-readonly`. See
[deploy/kubernetes/README.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/kubernetes/README.md).

> **One replica only.** The scheduler runs inside the process; a second replica would run every check twice.
> The Deployment uses the `Recreate` strategy for the same reason. Set `WDT_SCHEDULER=false` if you run extra
> replicas for availability and start runs elsewhere.

## Option C — Local Python

```sh
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# demo
WDT_DEMO=true APP_PASSWORD=demo uvicorn app.main:app --reload

# real configuration
WDT_CONFIG=config/environments.yaml APP_PASSWORD=... uvicorn app.main:app --reload
```

The application does **not** read `.env` itself; export the variables (or use Docker, which passes the file
with `env_file`). Python 3.11–3.13 is supported; `tzdata` installs the timezone database, so the configured
`TZ` works on slim images too.

## TLS and the reverse proxy

Put any TLS-terminating proxy in front; the app listens on `0.0.0.0:8080` inside the container and is
published on loopback by compose.

```caddy
triage.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

```nginx
server {
    listen 443 ssl;
    server_name triage.example.com;
    # ssl_certificate ...;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then set:

```sh
COOKIE_SECURE=true
FORWARDED_ALLOW_IPS=<proxy address or CIDR>
```

`FORWARDED_ALLOW_IPS` is read by uvicorn (`--proxy-headers`). Keep it to the proxy only: `*` would let any
client spoof `X-Forwarded-For`. For SSO in front of the app, continue with
[SSO proxy authentication](SSO-Proxy-Auth).

## Verify the installation

```sh
curl -fsS http://127.0.0.1:8080/healthz     # liveness: process is up
curl -fsS http://127.0.0.1:8080/readyz      # readiness: startup and configuration done
curl -fsS http://127.0.0.1:8080/metrics     # needs an admin session or METRICS_TOKEN
```

- `/healthz` never touches Wazuh; a failing Indexer must not restart the container.
- `/readyz` deliberately makes no Indexer call either, so an outage never removes the UI that explains it.
- Both are unauthenticated and safe for probes.
- The first login uses `APP_PASSWORD`; the login page mentions `VIEWER_PASSWORD` when the read-only role is on.

Then:

1. Open the environment page and press **Test connections**.
2. Press **Run check now** (or wait for the schedule) and confirm a report appears.
3. Approve or reject one finding; open **Knowledge base** and confirm the decision is stored.
4. Check `logs/audit.jsonl` for the login and the decision.

A successful startup logs the configured environments, the schedule, the audit file and any security warnings.
In production, `app/security.py` **refuses to start** on: `WDT_DEMO=true`, a missing or example `APP_PASSWORD`,
a missing `APP_SECRET`, `VIEWER_PASSWORD` equal to the admin password, `COOKIE_SECURE=false`, TLS verification
disabled for an endpoint, or `rule_deploy.enabled` without credentials. See
[docs/security-exceptions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md) for the two deliberate lab overrides.

## Upgrade and rollback

The application is stateless: reports and the knowledge base are documents in the Wazuh Indexer
(`daily-triage-*`). There is no database migration.

```sh
# Docker Compose (with a pinned tag)
docker compose pull
docker compose up -d
docker compose exec triage python -m app.check

# Helm
helm upgrade wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --version 0.1.3 -f my-values.yaml
helm rollback wazuh-daily-triage 1     # if needed
```

Read [CHANGELOG.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/CHANGELOG.md) before upgrading: configuration keys occasionally change. Existing
runs stay searchable; `run_retention_days` (YAML) prunes old run documents only, never the knowledge base.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Container exits with `refusing to start in production` | The message names the variable. Set a real `APP_PASSWORD`, `APP_SECRET`, `COOKIE_SECURE=true`, or fix TLS verification. |
| `FileNotFoundError: no config file and WAZUH_INDEXER_URL is not set` | No `config/environments.yaml` and no `WAZUH_INDEXER_URL` in the environment. Create one of them. |
| `502` from the proxy, container healthy | The proxy points at the wrong port (8080) or host; check `docker compose ps`. |
| Login loops back to `/login` | `COOKIE_SECURE=true` over plain HTTP, or the proxy strips cookies. Use HTTPS or set `COOKIE_SECURE=false` for a local test only. |
| `ZoneInfoNotFoundError` / unknown timezone | Set `TZ` to an IANA name (`Europe/Istanbul`) and keep `tzdata` installed. |
| TLS error to Wazuh | Mount the CA under `config/certs/` and set `ca_file` (or `WAZUH_CA_FILE`); do not use `verify_tls: false` in production. |
| No report at the scheduled time | The container must stay running (the scheduler is in-process), `schedule.enabled` must be true, and the clock/timezone must match `TZ`. |
| Model errors in the report | Run **Test connections**; check `LLM_*`, the base URL and the token budget (`max_tokens`). |

Next: [Configuration](Configuration) · [SSO proxy authentication](SSO-Proxy-Auth) ·
[Viewer mode](Viewer-Mode) · [MCP server](MCP)

---

[English](Installation) · [Türkçe](Installation-TR)
