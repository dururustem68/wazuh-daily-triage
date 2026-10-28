# Other data sources — Prometheus, Loki, Kubernetes (read-only)

Wazuh tells you *what* happened; the cause is often elsewhere (a pod restart, an OOM kill, a full disk, a
service error). With these sources the AI — in daily runs, incident drafts and over [MCP](mcp.md) — can
check it instead of asking you to.

```yaml
environments:
  - id: prod
    sources:
      prometheus: {url: "http://kube-prometheus-stack-prometheus.monitoring:9090"}
      loki: {url: "http://loki-gateway.monitoring", org_id: ""}        # username/password/bearer_token optional
      kubernetes:
        enabled: true          # needs the rbac-readonly component (in-cluster service account)
        namespaces: []         # optional allow-list
        pod_logs: true
```

| Tool | Notes |
|---|---|
| `prom_query`, `prom_range` | PromQL; range results are summarised (min/max/last + ≤ 60 points, ≤ 20 series) |
| `loki_query`, `loki_labels` | LogQL; ≤ 500 lines, newest first; metric queries supported |
| `k8s_get` | pods (restarts, last termination reason), nodes (Ready, pressure, kernel), events, deployments, statefulsets, daemonsets, replicasets, jobs, cronjobs, services, ingresses, PVCs, namespaces. **Never secrets or configmaps.** |
| `k8s_logs` | last ≤ 1000 lines of a pod (optionally the previous, crashed container) |

Kubernetes RBAC: add `components/rbac-readonly` to your overlay. It creates a service account with
`get`/`list` on exactly the resources above and mounts its token into the pod only.

Data from these sources goes to your LLM like alert data does; `privacy.mode: mask` pseudonymises personal data
and removes secrets in everything sent to the model. Logs can contain personal data — decide which namespaces the AI may read.
