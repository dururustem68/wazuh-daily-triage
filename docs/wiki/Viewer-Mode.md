# Viewer mode (read-only role)

A second password lets colleagues read everything without changing anything. It is intended for managers,
auditors, SOC shift leads and application owners who need the reports and the open recommendations, not the
ability to run triage or deploy rules.

![Read-only viewer](images/viewer-mode.png)

## Enable it

```sh
# .env
VIEWER_PASSWORD=<a strong password, different from APP_PASSWORD>
AUTH_DISABLED=false          # viewer mode is an app-password feature
```

Restart the container. The login page then says that a read-only viewer sign-in is available. Both passwords
use the same form; the application decides the role from the password that matched:

| Password | Role | Session |
|---|---|---|
| `APP_PASSWORD` | `admin` | signed cookie, 12 hours |
| `VIEWER_PASSWORD` | `viewer` | signed cookie, 12 hours |

In production, startup **refuses** a `VIEWER_PASSWORD` that equals `APP_PASSWORD`. An empty value simply
disables the role.

## What the viewer may do

| Permission | Admin | Viewer | Covers |
|---|---|---|---|
| `read` | ✓ | ✓ | dashboard, reports, recommendation inbox, knowledge base and its YAML export, audit report, promotion package view, copies and PDFs |
| `run` | ✓ | – | start a triage run, liveness check, connection test, notification test |
| `decide` | ✓ | – | finding decisions, answering questions, inbox actions, incident records |
| `knowledge` | ✓ | – | create/update/delete knowledge entries, import |
| `deploy` | ✓ | – | approve/deploy/undeploy/promote rule drafts |
| `admin` | ✓ | – | environment-level operations and `/metrics` without `METRICS_TOKEN` |

The matrix lives in `app/authz.py`; the HTTP middleware checks it for **every** route. Hiding a button is never
the control: a crafted `POST` gets `403` and is written to the audit trail as `denied:<permission>`.

### Known cosmetic limitation in 0.7.0

Some write controls (for example **Run check now** and the decision buttons) are still rendered for a viewer.
They fail closed — the server rejects the request — but they are visible. Treat the 403 as the boundary, not
the absence of a button.

## Limit the environments a viewer sees

When production, staging and customer instances share one installation, scope each role:

```sh
VIEWER_ENVS=staging,lab        # empty = all environments
ADMIN_ENVS=prod,staging,lab    # optional, empty = all
```

A viewer who opens a URL for an environment outside the list gets a `403` page, and the denial is audited. The
same check runs inside the page handlers, so a guessed environment id does not leak data.

## Verify

1. Sign out, then sign in with `VIEWER_PASSWORD`.
2. The sidebar shows a **read-only** pill; the dashboard shows reports and recommendations.
3. Open a finding: the decision buttons and **Incident record draft** do nothing useful — the request is
   rejected with `403`.
4. Try **Run check now**: the run does not start and no run appears in the list.
5. Check the audit trail:

```sh
tail -n 5 logs/audit.jsonl
# {"action":"denied","actor":"ui","role":"viewer","result":"denied:run",...}
```

6. `GET /metrics` with a viewer session returns `403` unless `METRICS_TOKEN` is configured (then the bearer
   token, not the session, is the credential).

## Operational notes

- **Sessions last 12 hours.** `POST /logout` clears the cookie.
- **Rotating the password does not end existing sessions.** The cookie contains the role and an expiry, not the
  password. Change `APP_SECRET` to invalidate every session immediately.
- **The password is shared by all viewers.** There are no individual viewer accounts and no per-viewer audit
  identity: the audit trail records the role `viewer` with the shared actor `ui` (only login records say
  `viewer`). If you need named read-only users, use an SSO proxy
  — but see the caveat below.
- **No CSRF risk from GETs.** All state-changing operations are `POST`/`DELETE` and go through the same
  permission check.

## Viewer mode vs. SSO

These two are mutually exclusive in the current design:

- `AUTH_DISABLED=true` makes **every** request an admin, because there is no group/role mapping from the proxy.
  `VIEWER_PASSWORD` is then ignored for authorization.
- `AUTH_DISABLED=false` keeps the app login and therefore supports the viewer role, but then the proxy must not
  authenticate users (or must only wrap, not replace, the app login).

If you need SSO for identity **and** read-only users, the practical options are:

1. Use app passwords and give the viewer password to the people who need read-only access.
2. Run a second instance with its own configuration and restrict what it can do at the network/proxy layer.
3. Enforce read-only at the proxy with a separate host and an allow-list of methods, and accept that the app
   still sees an admin — **not recommended**, because a `GET` link does not protect the app.

## Security checklist

- `VIEWER_PASSWORD` is long, unique and different from `APP_PASSWORD`.
- `APP_SECRET` is set, so sessions survive restarts and cannot be forged.
- `COOKIE_SECURE=true` behind TLS.
- `ENVIRONMENT=production` so the startup checks run.
- `VIEWER_ENVS` limits staging/customer data when the installation is shared.
- Audit shipping is configured (`logs/audit.jsonl` rotates at 20 MB, keeps three generations). The file is
  hash-chained: every line carries `prev` and `hash`, so an edited or deleted line is detectable.

  ```sh
  docker compose exec triage python -c "from app import auditlog; print(auditlog.verify())"
  # {'ok': True, 'lines': 42, 'broken': None, 'file': 'logs/audit.jsonl'}
  ```

See also [docs/permissions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md) for the least-privilege Wazuh accounts and the audit format.

---

[English](Viewer-Mode) · [Türkçe](Viewer-Mode-TR)
