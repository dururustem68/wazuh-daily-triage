# Kubernetes

Kustomize manifests: `base/` (Deployment, Service, optional NetworkPolicy) and `example/` (an overlay with
configuration and secrets).

```sh
cp -r deploy/kubernetes/example ~/triage-overlay && cd ~/triage-overlay
# point the base at the repository:
sed -i 's#  - ../base .*#  - https://github.com/dururustem68/wazuh-daily-triage//deploy/kubernetes/base?ref=v0.1.2#' kustomization.yaml
cp secret.env.example secret.env && vi secret.env environments.yaml context.md
kubectl apply -k .
kubectl -n wazuh-daily-triage rollout status deploy/wazuh-daily-triage
kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage -- python -m app.check
kubectl -n wazuh-daily-triage port-forward svc/wazuh-daily-triage 8080:8080   # http://127.0.0.1:8080
```

Notes

- **One replica only.** The scheduler runs inside the process; more replicas would run each check more than
  once. The Deployment uses the `Recreate` strategy for the same reason.
- **Stateless.** Reports, knowledge base and chat live in the Wazuh Indexer (`daily-triage-*`); no PVC is needed.
- **Hardened by default:** non-root, read-only root filesystem, all capabilities dropped, no service account
  token, `restricted` Pod Security level.
- **Same cluster as Wazuh?** Use the in-cluster service names (example above) — the indexer never has to be
  exposed. Otherwise make sure pods can reach the indexer (9200) and API (55000).
- **Exposing the UI:** start with `port-forward`. For an Ingress, put SSO (oauth2-proxy, Authentik, Keycloak
  forward-auth) in front and set `AUTH_DISABLED=true`, or keep the app password and set `COOKIE_SECURE=true`
  behind TLS. Set `FORWARDED_ALLOW_IPS` to your ingress controller's pod CIDR, never `*`.
- **NetworkPolicy:** `base/networkpolicy.yaml` is a starting point; adjust the namespace label and Wazuh
  addresses before adding it to your overlay.
