# Wiki source (bilingual)

This folder holds the source of the project wiki: 22 pages in English, each with a Turkish version, the home
page also in Spanish and French, and one screenshot folder. The pages are plain Markdown and are published to the GitHub wiki repository; they are not built by
any tool.

| Page | English | Türkçe | Audience |
|---|---|---|---|
| Landing page | [`Home.md`](Home.md) | [`Home-TR.md`](Home-TR.md) | everyone — also [`Home-ES.md`](Home-ES.md), [`Home-FR.md`](Home-FR.md) |
| Installation | [`Installation.md`](Installation.md) | [`Installation-TR.md`](Installation-TR.md) | operator installing it |
| Configuration | [`Configuration.md`](Configuration.md) | [`Configuration-TR.md`](Configuration-TR.md) | operator, day 2 |
| Features | [`Features.md`](Features.md) | [`Features-TR.md`](Features-TR.md) | operator, SOC lead |
| Privacy (GDPR / KVKK) | [`Privacy.md`](Privacy.md) | [`Privacy-TR.md`](Privacy-TR.md) | DPO, auditor, operator |
| SSO proxy authentication | [`SSO-Proxy-Auth.md`](SSO-Proxy-Auth.md) | [`SSO-Proxy-Auth-TR.md`](SSO-Proxy-Auth-TR.md) | platform / identity team |
| Viewer mode | [`Viewer-Mode.md`](Viewer-Mode.md) | [`Viewer-Mode-TR.md`](Viewer-Mode-TR.md) | SOC lead, auditor |
| MCP server | [`MCP.md`](MCP.md) | [`MCP-TR.md`](MCP-TR.md) | AI tooling, integrator |
| Watch (urgent alerts) | [`Watch.md`](Watch.md) | [`Watch-TR.md`](Watch-TR.md) | operator, SOC on call |
| Backup and retention | [`Backup.md`](Backup.md) | [`Backup-TR.md`](Backup-TR.md) | operator, auditor |
| Getting started | [`Getting-Started.md`](Getting-Started.md) | [`Getting-Started-TR.md`](Getting-Started-TR.md) | first-time installer |
| User guide | [`User-Guide.md`](User-Guide.md) | [`User-Guide-TR.md`](User-Guide-TR.md) | reviewer, SOC analyst |
| Rule lifecycle | [`Rule-Lifecycle.md`](Rule-Lifecycle.md) | [`Rule-Lifecycle-TR.md`](Rule-Lifecycle-TR.md) | administrator approving rules |
| Kubernetes | [`Kubernetes.md`](Kubernetes.md) | [`Kubernetes-TR.md`](Kubernetes-TR.md) | platform engineer |
| Security model | [`Security-Model.md`](Security-Model.md) | [`Security-Model-TR.md`](Security-Model-TR.md) | security lead, DPO, auditor |
| Security checklist | [`Security-Checklist.md`](Security-Checklist.md) | [`Security-Checklist-TR.md`](Security-Checklist-TR.md) | whoever signs off go-live |
| Troubleshooting | [`Troubleshooting.md`](Troubleshooting.md) | [`Troubleshooting-TR.md`](Troubleshooting-TR.md) | operator |
| Upgrade | [`Upgrade.md`](Upgrade.md) | [`Upgrade-TR.md`](Upgrade-TR.md) | operator |
| Compatibility | [`Compatibility.md`](Compatibility.md) | [`Compatibility-TR.md`](Compatibility-TR.md) | evaluator, operator |
| Development | [`Development.md`](Development.md) | [`Development-TR.md`](Development-TR.md) | contributor |
| Scenarios | [`Scenarios.md`](Scenarios.md) | [`Scenarios-TR.md`](Scenarios-TR.md) | new user |
| FAQ and glossary | [`FAQ.md`](FAQ.md) | [`FAQ-TR.md`](FAQ-TR.md) | everyone |

`_Sidebar.md` is the navigation that GitHub renders on every wiki page. `images/` holds the screenshots,
taken from a running 0.11.0 demo instance.

## Screenshots

| File | Page | Shows |
|---|---|---|
| `images/login.png` | Home, Installation | the sign-in page, including the viewer hint |
| `images/dashboard.png` | Home, User guide | the dashboard: key figures, alert volume, severity, ATT&CK tactic strip, top lists |
| `images/attack.png` | User guide | the MITRE ATT&CK matrix |
| `images/report.png` | Home, MCP | a daily report with findings and evidence |
| `images/inbox.png` | — | the recommendation inbox |
| `images/knowledge.png` | — | the knowledge base |
| `images/viewer-mode.png` | Viewer mode | the same UI signed in with `VIEWER_PASSWORD` |
| `images/about.png` | Features | the About page: features per environment, MCP setup |

They were captured headlessly with Playwright against the demo (`WDT_DEMO=true`, `LLM_PROVIDER=mock`, synthetic
data), 1280×900 at device scale 1.5, light theme. To refresh them, start the demo, then capture the same pages
(the report image is scrolled to the first finding with ATT&CK tags). Never use screenshots showing real customer alerts.

## How the links work

- Pages link to each other by **bare page name**: `[Configuration](Configuration)`, not `Configuration.md` and
  not a URL. That is what the GitHub wiki expects; it resolves to `/wiki/Configuration` and needs no edit when
  the wiki is moved or renamed.
- Turkish pages link to `...-TR` names; each page ends with a two-line language switcher.
- Links to repository documents (`docs/permissions.md`, `deploy/kubernetes/README.md`, `CHANGELOG.md`, …) are
  **absolute GitHub URLs**. A relative link would work in the repository but break inside the wiki, which is a
  separate git repository. Keep it that way if you add links.
- Images are referenced as `images/foo.png`, relative to the page. The `images/` folder must be copied to the
  wiki repository too.
- Avoid `#anchor` links on Turkish pages: GitHub slugifies Turkish characters unpredictably. Link to the page
  instead.

## Publish to the GitHub wiki

The wiki is its own git repository (`<repo>.wiki.git`). Pages in `docs/wiki/` are the source of truth; copy them
across whenever they change.

### First time only

1. In the GitHub repository: **Settings → Features → Wikis** must be enabled.
2. Open the **Wiki** tab and create any first page through the web UI (for example “Home”, one line of text).
   GitHub does not create the `.wiki.git` repository until the first page exists, so cloning before this step
   fails with “repository not found”.
3. Clone it next to the project:

   ```sh
   git clone https://github.com/dururustem68/wazuh-daily-triage.wiki.git
   ```

### Every update

`README.md` (this file) is a maintainer note and is **not** published; every other `*.md` file is copied:

```sh
# from the project root
WIKI=../wazuh-daily-triage.wiki
for p in docs/wiki/*.md; do
  [ "$(basename "$p")" = README.md ] || cp "$p" "$WIKI/"
done
mkdir -p "$WIKI/images"
cp docs/wiki/images/*.png "$WIKI/images/"

cd "$WIKI"
git add -A
git commit -m "wiki: sync from docs/wiki (0.11.0)"
git push
```

In PowerShell:

```powershell
$wiki = '..\wazuh-daily-triage.wiki'
Get-ChildItem docs\wiki\*.md | Where-Object Name -ne 'README.md' |
  ForEach-Object { Copy-Item $_.FullName $wiki -Force }
New-Item -ItemType Directory -Force "$wiki\images" | Out-Null
Copy-Item docs\wiki\images\*.png "$wiki\images" -Force
git -C $wiki add -A
git -C $wiki commit -m "wiki: sync from docs/wiki (0.11.0)"
git -C $wiki push
```

`Home.md` becomes the wiki landing page, `_Sidebar.md` the navigation on every page, and `Home-TR.md` is the
Turkish landing page linked from the sidebar and from `Home.md`.

### Alternative: edit in the browser

Small fixes can be made directly in the GitHub wiki UI, but then copy the change back into `docs/wiki/`,
otherwise the next sync silently reverts it.

## Conventions

- One topic per page; do not add a page without adding it to `_Sidebar.md` (both languages).
- Every page starts with who it is for, and ends with the version it applies to and the review date
  (`*Applies to 0.11.0 · reviewed 2026-11-11*`). Update that line when you re-check a page against a release.
- A command goes into a page only after it was run against the stated version. Say "tested", "expected" or
  "not supported" with the meanings defined on the Compatibility page; never "should work".
- Dangerous operations state their effect, prerequisite, confirmation and rollback.
- README and wiki do not repeat each other: the README is the short version and links here; exact reference
  material (permissions, deployment API, notification fields) stays in `docs/*.md` and is linked, not copied.
- Every page ends with `[English](Page) · [Türkçe](Page-TR)`.
- Keep commands copy-pasteable and version-pinned: `0.11.0`, chart `0.3.0`.
- Update the version string in `Home.md`, `Home-TR.md`, `_Sidebar.md` when the release changes.
- Never put a real password, token, hostname or customer alert in a page or a screenshot.

---

## Türkçe özet

`docs/wiki/` bu wiki'nin kaynağıdır: 22 İngilizce sayfa, her birinin Türkçe eşi ve `images/` altında ekran görüntüleri.
Yayınlamak için GitHub'da wiki'yi bir kez açın (Settings → Wikis ve Wiki sekmesinde ilk sayfa), sonra
`wazuh-daily-triage.wiki.git` deposunu klonlayıp bu dizindeki `*.md` ve `images/` içeriğini kopyalayın, commit
edip push edin. Sayfa bağlantıları `Configuration` gibi çıplak adlarla yazılır (`.md` eklenmez); depo
belgelerine giden bağlantılar ise wiki ayrı bir depo olduğu için mutlak GitHub adresi olarak durur. Ekran
görüntüleri 0.11.0 demo örneğinden alınmıştır; gerçek müşteri verisi içeren görüntü kullanmayın.
