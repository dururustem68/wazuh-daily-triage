# Wiki source (bilingual)

This folder holds the source of the project wiki: six pages in English, six in Turkish, one screenshot
folder. The pages are plain Markdown and are published to the GitHub wiki repository; they are not built by
any tool.

| Page | English | Türkçe | Audience |
|---|---|---|---|
| Landing page | [`Home.md`](Home.md) | [`Home-TR.md`](Home-TR.md) | everyone |
| Installation | [`Installation.md`](Installation.md) | [`Installation-TR.md`](Installation-TR.md) | operator installing it |
| Configuration | [`Configuration.md`](Configuration.md) | [`Configuration-TR.md`](Configuration-TR.md) | operator, day 2 |
| SSO proxy authentication | [`SSO-Proxy-Auth.md`](SSO-Proxy-Auth.md) | [`SSO-Proxy-Auth-TR.md`](SSO-Proxy-Auth-TR.md) | platform / identity team |
| Viewer mode | [`Viewer-Mode.md`](Viewer-Mode.md) | [`Viewer-Mode-TR.md`](Viewer-Mode-TR.md) | SOC lead, auditor |
| MCP server | [`MCP.md`](MCP.md) | [`MCP-TR.md`](MCP-TR.md) | AI tooling, integrator |

`_Sidebar.md` is the navigation that GitHub renders on every wiki page. `images/` holds the screenshots,
taken from a running 0.7.0 demo instance.

## Screenshots

| File | Page | Shows |
|---|---|---|
| `images/login.png` | Home, Installation | the sign-in page, including the viewer hint |
| `images/dashboard.png` | Home | watch board with findings, open questions and the environment card |
| `images/report.png` | Home, MCP | a daily report with findings and evidence |
| `images/inbox.png` | — | the recommendation inbox |
| `images/knowledge.png` | — | the knowledge base |
| `images/viewer-mode.png` | Viewer mode | the same UI signed in with `VIEWER_PASSWORD` |

They were captured headlessly with Playwright against the demo (`WDT_DEMO=true`, `LLM_PROVIDER=mock`, synthetic
data), 1280×900 at device scale 1.5. To refresh them, start the demo, run one check, then capture the same
pages. Never use screenshots showing real customer alerts.

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

`README.md` (this file) is a maintainer note and is **not** published, so the pages are copied by name:

```sh
# from the project root
WIKI=../wazuh-daily-triage.wiki
for p in Home Home-TR Installation Installation-TR Configuration Configuration-TR \
         SSO-Proxy-Auth SSO-Proxy-Auth-TR Viewer-Mode Viewer-Mode-TR MCP MCP-TR _Sidebar; do
  cp "docs/wiki/$p.md" "$WIKI/"
done
mkdir -p "$WIKI/images"
cp docs/wiki/images/*.png "$WIKI/images/"

cd "$WIKI"
git add -A
git commit -m "wiki: sync from docs/wiki (0.7.0)"
git push
```

In PowerShell:

```powershell
$wiki = '..\wazuh-daily-triage.wiki'
'Home','Home-TR','Installation','Installation-TR','Configuration','Configuration-TR',
'SSO-Proxy-Auth','SSO-Proxy-Auth-TR','Viewer-Mode','Viewer-Mode-TR','MCP','MCP-TR','_Sidebar' |
  ForEach-Object { Copy-Item "docs\wiki\$_.md" $wiki -Force }
New-Item -ItemType Directory -Force "$wiki\images" | Out-Null
Copy-Item docs\wiki\images\*.png "$wiki\images" -Force
git -C $wiki add -A
git -C $wiki commit -m "wiki: sync from docs/wiki (0.7.0)"
git -C $wiki push
```

`Home.md` becomes the wiki landing page, `_Sidebar.md` the navigation on every page, and `Home-TR.md` is the
Turkish landing page linked from the sidebar and from `Home.md`.

### Alternative: edit in the browser

Small fixes can be made directly in the GitHub wiki UI, but then copy the change back into `docs/wiki/`,
otherwise the next sync silently reverts it.

## Conventions

- One topic per page; do not add a page without adding it to `_Sidebar.md` (both languages).
- Every page ends with `[English](Page) · [Türkçe](Page-TR)`.
- Keep commands copy-pasteable and version-pinned: `0.7.0`, chart `0.1.3`.
- Update the version string in `Home.md`, `Home-TR.md`, `_Sidebar.md` when the release changes.
- Never put a real password, token, hostname or customer alert in a page or a screenshot.

---

## Türkçe özet

`docs/wiki/` bu wiki'nin kaynağıdır: altı İngilizce, altı Türkçe sayfa ve `images/` altında ekran görüntüleri.
Yayınlamak için GitHub'da wiki'yi bir kez açın (Settings → Wikis ve Wiki sekmesinde ilk sayfa), sonra
`wazuh-daily-triage.wiki.git` deposunu klonlayıp bu dizindeki `*.md` ve `images/` içeriğini kopyalayın, commit
edip push edin. Sayfa bağlantıları `Configuration` gibi çıplak adlarla yazılır (`.md` eklenmez); depo
belgelerine giden bağlantılar ise wiki ayrı bir depo olduğu için mutlak GitHub adresi olarak durur. Ekran
görüntüleri 0.7.0 demo örneğinden alınmıştır; gerçek müşteri verisi içeren görüntü kullanmayın.
