# Wazuh Daily Triage

**KI-gestützte tägliche Überprüfung für [Wazuh](https://wazuh.com) SIEM.** Jeden Morgen prüft es, ob Ihr SIEM
wirklich läuft, trennt echtes Risiko von bekanntem Rauschen, schreibt einen kurzen Diagnosebericht zurück in Ihren
Wazuh Indexer, fragt Sie nur dort, wo eine menschliche Entscheidung nötig ist — und merkt sich Ihre Antworten beim
nächsten Mal.

Eigene KI mitbringen: Anthropic, OpenAI, Azure OpenAI oder jeder OpenAI-kompatible Endpunkt (Ollama, vLLM, LM Studio,
LiteLLM). Ein Docker-Container, standardmäßig schreibgeschützt gegenüber Wazuh. Kritische Alarme und
Laufzusammenfassungen gehen an E-Mail, Telegram, Microsoft Teams, Slack, Discord, ntfy oder einen generischen
Webhook.

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Español](README.es.md) · [KI-Anbieter](docs/providers.md) · [Benachrichtigungen](docs/notifications.md) · [Berechtigungen & Netzwerk](docs/permissions.md) · [Regelbereitstellung](docs/rule-deployment.md) · [Architektur](docs/architecture.md) · [Kompatibilität](docs/compatibility.md) · [Mitwirken](CONTRIBUTING.md) · [Sicherheit](SECURITY.md)

![Bericht](docs/screenshot-report.png)

| Empfehlungseingang | Wissensdatenbank und Regelentwürfe |
|---|---|
| ![Eingang](docs/screenshot-inbox.png) | ![Wissensdatenbank](docs/screenshot-knowledge.png) |

<img src="docs/screenshot-audit-pdf.png" alt="Monatlicher Prüfbericht (PDF)" width="430">

## Warum

Wenn Ihre Morgenroutine mit derselben Wazuh-Routine beginnt — *fließen Daten, sind Agenten verbunden, was liegt bei
Stufe 7+, was davon ist das übliche Rauschen, was ist echt* — erledigt dieses Werkzeug die Fleißarbeit und ruft Sie
nur dort, wo eine Entscheidung nötig ist. Es kodiert hart erarbeitete Prüfgewohnheiten: Gesundheit vor Alarmen,
Verteilungen statt Durchschnitte, „gleiche Anzahl auf jedem Agenten = Feed-Ereignis“, „Null bedeutet nicht, dass die
Regel funktioniert“, Herabstufen statt Stummschalten.

## Funktionen

- **Zeitgesteuerte Läufe** pro Umgebung (ein- oder mehrmals täglich + Wochentage). Das Fenster ist „seit dem letzten
  erfolgreichen Lauf“, sodass der Montagmorgen das Wochenende abdeckt.
- **Zuerst deterministische Erfassung** — unabhängig von der KI: letzter Alarmzeitpunkt und leere Stunden (blinde
  Flecken), Indexer-Zustand und Speicherplatz, Manager-Daemons, inaktive Agenten, Fehler in `ossec.log`,
  Stufenverteilung, Gruppen hoher Stufe (Regel × Agent × erstes/letztes Auftreten × Quell-IP × Beispiel), Vergleich
  mit dem vorherigen Fenster, Regel-IDs, die **seit 14 Tagen zum ersten Mal auftreten**, beobachtete Regeln,
  Schwachstellenzusammenfassung.
- **KI-Diagnose** — das Modell liest die Zusammenfassung plus Ihre Wissensdatenbank, geht mit schreibgeschützten
  Werkzeugen tiefer (Zeitverteilung, IP-Profil, ±30-Minuten-Korrelation, Logtest, Regeldefinitionen) und liefert
  einen strukturierten Bericht: *echter Vorfall, untersuchen, Erkennungslücke, Falschpositiv, Baseline-Anstieg …*
  Es entwirft Wazuh-Regeln und prüft sie auf XML-Fehler, OS_Regex-Fallen und ID-Kollisionen.
- **Versandfertige Regelentwürfe** — jeder Entwurf kommt mit Copy-Paste-Befehlen für den Manager (Sicherung,
  `wazuh-analysisd -t`, Neustart, Zurückrollen). Optional schreibt **Genehmigen und bereitstellen** den Entwurf über
  die Wazuh-API in eine dedizierte Regeldatei, validiert, startet neu, prüft das Laden, führt einen beidseitigen
  Logtest aus und rollt bei jedem Fehler zurück; Entwürfe, die Alarme stummschalten oder herabstufen, erfordern eine
  zweite Bestätigung durch Eingabe der Regel-IDs ([docs/rule-deployment.md](docs/rule-deployment.md)). Standardmäßig
  aus.
- **Es fragt Sie** — „War dieser SSH-Login Ihrer?“ Ihre Antwort landet in der Wissensdatenbank und ist Kontext für
  den nächsten Lauf.
- **Wissensdatenbank** — bekanntes Rauschen, Entscheidungen („X nicht vorschlagen“), offene Punkte, Lehren,
  „morgen danach schauen“-Anfragen. KI-Vorschläge haben **keine Wirkung, bis Sie sie genehmigen**. Bringen Sie Ihre
  vorhandenen Notizen per YAML-Import/-Export mit (UI oder `python -m app.kb`), wiederholbar ohne Duplikate.
- **Empfehlungseingang** — Funde einzeln, über Läufe hinweg dedupliziert; eine Entscheidung erledigt alle
  Vorkommen. Funde, die eine Prüfung auf einem Server erfordern, enthalten exakte schreibgeschützte Befehle, und
  ein Klick kopiert den Fund samt Befehlen, damit Sie die Ausgabe dort einfügen können, wo Sie arbeiten.
- **Benachrichtigungen per E-Mail, Telegram, Microsoft Teams, Slack, Discord, ntfy oder generischem Webhook** —
  kritische Situationen (SIEM stumm, Indexer rot, echte Vorfälle), ohne dass dasselbe Element bei jedem Lauf
  wiederholt wird; optional eine kurze Zusammenfassung nach jedem Lauf und Regelbereitstellungen
  ([docs/notifications.md](docs/notifications.md)).
- **Live-Verifikation** — eine bereitgestellte, genehmigte oder übernommene Regel wird nach jedem Lauf gegen echte
  Ereignisse geprüft: „live bestätigt 12× (zuletzt …)“ oder „seit 5 Tagen nicht gesehen“. `logtest passed` ist kein
  Beweis; ein echtes Ereignis ist es.
- **Dauerhaft machen** — für einen getesteten Entwurf ein Übernahmepaket für *Ihre* Konfigurationsverwaltung: der
  Regelblock mit Herkunft, ein Skript (Sicherung → anhängen → `wazuh-analysisd -t` auf dem laufenden Manager →
  mit `kubectl apply -k` oder Neustart ausrollen → prüfen, ob geladen) und ein Entwurf eines § für Ihren
  Alarmkatalog.
- **Sättigung des Mailkanals** — mit gesetztem `mail:` zeigt jeder Lauf die Stunden, in denen eine Flut
  `email_maxperhour` überschritt, und die anderen Regeln, die in diesen Stunden ausgelöst haben und möglicherweise
  nie gemailt wurden.
- **Abdeckung und Schwachstellen-SLA** — Agenten nach Status/Version/Node, erwartete, aber fehlende Agenten aus
  einer Inventarliste und aktive Schwachstellen, die länger als die SLA pro Schweregrad offen sind.
- **Monatlicher Prüfbericht** — Alarmvolumen, Läufe, Funde und Ihre Entscheidungen, Regeländerungen (wer, wann, was
  herabgestuft wurde), SIEM-Ausfälle aus der Live-Prüfung, Abdeckung und Schwachstellen-SLA. Deterministisch (keine
  KI), als PDF oder Markdown herunterladbar — Nachweis für ISO 27001 / ISMS-Reviews.
- **Anomalien ohne KI** — jeder Lauf vergleicht Regel-×-Agenten-Zahlen mit den vorherigen 14 Tagen: Ausreißer
  (z-Score) und Regeln, die auf einem Agenten zum ersten Mal auslösen; die KI startet von dort.
- **Über Wazuh hinaus (optional)** — schreibgeschützte Prometheus-, Loki- und Kubernetes-Werkzeuge (Pods, Neustarts,
  OOM-Kills, Node-Druck, Events, Pod-Logs; niemals Secrets), damit die Ursache eines Alarms geprüft statt geraten
  wird ([docs/sources.md](docs/sources.md)).
- **Entwürfe für Vorfallprotokolle** — ein Klick auf einen Fund: die KI sammelt die Belege und füllt Ihre
  Vorfallvorlage (Zeitachse, Ursache, Auswirkung, Belegabfragen, Maßnahmen); bearbeiten, herunterladen oder als
  Zammad- oder Jira-Ticket öffnen.
- **MCP-Server** — dieselben schreibgeschützten Werkzeuge für Claude Desktop oder jeden MCP-Client, damit Sie mit
  Live-Daten aus Ihrem eigenen Assistenten untersuchen können ([docs/mcp.md](docs/mcp.md)).
- **Evaluation** — `python -m app.eval` spielt Tage nach, die Sie selbst geprüft haben, und bewertet die KI (Recall,
  als Vorfälle gemeldetes Rauschen, Token): Modelle und Prompts mit Zahlen vergleichen
  ([docs/eval.md](docs/eval.md)).
- **Kopierfertige Ausgabe** — jeder Fund und jede Frage hat eine Kopierschaltfläche (Klartext: Belege, Empfehlung,
  Befehle) für Tickets, E-Mail oder ein Terminal.
- **In Wazuh selbst gespeichert** — `daily-triage-runs`- und `daily-triage-knowledge`-Indizes im Indexer jeder
  Umgebung. Keine zusätzliche Datenbank. Ein optionales `run_retention_days` entfernt alte Läufe; die
  Wissensdatenbank wird nie gelöscht.
- **Mehrere Umgebungen, mehrere Sprachen** (Englisch, Türkisch, Spanisch, Deutsch), KI-Überschreibung pro Umgebung
  (z. B. ein lokales Modell für regulierte Daten), Verbindungstest in UI und CLI.

## Schnellstart

### 1. Demo ausprobieren (kein Wazuh nötig)

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git && cd wazuh-daily-triage
cp .env.example .env
sed -i 's/^WDT_DEMO=.*/WDT_DEMO=true/; s/^LLM_PROVIDER=.*/LLM_PROVIDER=mock/; s/^APP_LANGUAGE=.*/APP_LANGUAGE=de/' .env
docker compose up -d --build
# http://127.0.0.1:8080 öffnen — Passwort: APP_PASSWORD aus .env
```

Die Demo verwendet synthetische Daten (Jenkins-Basic-Auth-Brute-Force, SSH-Versuche, ein getrennter Agent, eine
Schwachstellenwelle nach einem Update …). `mock` führt keine echte Analyse durch; setzen Sie die `LLM_*`-Variablen,
um ein echtes Modell mit denselben Daten auszuprobieren.

### 2. Ihr Wazuh verbinden — eine Umgebung, kein YAML

Erstellen Sie die schreibgeschützten Konten aus **[docs/permissions.md](docs/permissions.md)** und tragen Sie dann
in `.env` ein:

```sh
WDT_DEMO=false
LLM_PROVIDER=anthropic          # oder openai
LLM_MODEL=<Modell-ID Ihres Anbieters>
LLM_API_KEY=<Ihr Schlüssel>
WAZUH_INDEXER_URL=https://wazuh-indexer.example.internal:9200
WAZUH_INDEXER_USER=daily-triage
WAZUH_INDEXER_PASSWORD=...
WAZUH_API_URL=https://wazuh-manager.example.internal:55000   # optional
WAZUH_API_USER=daily-triage
WAZUH_API_PASSWORD=...
WAZUH_CA_FILE=/app/config/certs/root-ca.pem                   # Ihre CA nach ./config/certs/ kopieren
```

```sh
docker compose up -d
docker compose exec triage python -m app.check    # oder „Verbindungen testen“ auf der Umgebungsseite
```

### 3. Mehrere Umgebungen

```sh
cp config/environments.example.yaml config/environments.yaml
vi config/environments.yaml        # ein Block pro Wazuh; Secrets als ${VARS} aus .env
vi config/context/<env>.md         # ein paar Zeilen zur Beschreibung der Umgebung
```

`config/environments.yaml`, `config/context/*`, `config/seed/*`, `config/certs/` und `.env` sind von Git
ausgeschlossen.

### Kubernetes

Ein **[Helm-Chart](deploy/helm/wazuh-daily-triage)** sowie eine Kustomize-Basis, ein Beispiel-Overlay und optionale
Komponenten in **[deploy/kubernetes](deploy/kubernetes/README.md)** — ein Replikat, nicht root, schreibgeschütztes
Dateisystem, kein PVC (der Zustand liegt im Wazuh Indexer). Komponenten: `networkpolicy`, `ingress-nginx` (TLS,
cert-manager, Option für oauth2-proxy) und `ingress-traefik-authentik` (SSO).

## KI-Anbieter

Eigenen Schlüssel mitbringen. Vollständige Einrichtung für jeden Anbieter, inklusive Modellnamen und
Parameter-Eigenheiten: **[docs/providers.md](docs/providers.md)**.

| Anbieter | `LLM_PROVIDER` | `LLM_BASE_URL` | Beispiel `LLM_MODEL` |
|---|---|---|---|
| Claude (Anthropic) | `anthropic` | — | `claude-sonnet-5-5` |
| OpenAI | `openai` | `https://api.openai.com/v1` | `gpt-6.1-sol` ¹ |
| Google Gemini | `openai` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-3.8-flash` |
| DeepSeek | `openai` | `https://api.deepseek.com` | `deepseek-flash` |
| Azure OpenAI | `openai` | vollständige Deployment-URL mit `?api-version=` | Ihr Deployment |
| Ollama / vLLM / LM Studio / LiteLLM | `openai` | z. B. `http://ollama:11434/v1` | z. B. `qwen3:14b` |

¹ OpenAI-Reasoning-Modelle benötigen zusätzlich `LLM_TOKEN_PARAM=max_completion_tokens` und
`LLM_TEMPERATURE=none`.

Das Modell muss Tool- (Function-) Calling unterstützen. Jede Umgebung kann das Modell überschreiben (`llm:`-Block) —
z. B. ein lokales Modell für eine Umgebung, deren Daten Ihr Netzwerk nicht verlassen dürfen. `max_tool_steps`
begrenzt die Kosten pro Lauf.

## Benachrichtigungen — E-Mail, Telegram, Teams, Slack, Discord, ntfy, Webhook

| Wann | Einstellung (Standard) |
|---|---|
| SIEM stumm, Indexer rot, Manager-Daemon down, Indexer-Speicher ≥ 90 % | `on_critical_flags: true` |
| Fund mit Label *echter Vorfall* / Schweregrad *kritisch* | `on_real_incident: true`, `on_critical_findings: true` |
| Der Lauf selbst ist fehlgeschlagen | `on_run_error: false` |
| Kurze Zusammenfassung nach **jedem** Lauf (Zustand, Zahlen, wartende Empfehlungen) | `on_run_summary: false` |
| Ein Regelentwurf wurde bereitgestellt, zurückgerollt oder entfernt | `on_rule_deploy: true` |
| **Live-Prüfung alle 10 Minuten** (keine KI): Indexer/API nicht erreichbar, Daemon down, SIEM stumm, Speicher ≥ 90 % — Problem, Erinnerung, behoben | `on_liveness: true`, `liveness.interval_minutes` |

Dasselbe kritische Element wird innerhalb von `repeat_hours` (24) nicht wiederholt. Ein Kanal ist aktiv, sobald
seine Felder gesetzt sind; **Benachrichtigungen testen** auf der Umgebungsseite prüft alle.

```sh
# .env — beliebige Kombination von Kanälen
NOTIFY_UI_URL=https://triage.example.internal      # Link in Nachrichten
NOTIFY_ON_RUN_SUMMARY=true

TELEGRAM_BOT_TOKEN=123456789:AA...                 # @BotFather → /newbot
TELEGRAM_CHAT_ID=-1001234567890                    # siehe unten

TEAMS_WEBHOOK_URL=https://...                      # Kanal → Workflows → "Post to a channel when a webhook request is received"

SLACK_WEBHOOK_URL=https://hooks.slack.com/...      # Your Apps → Incoming Webhooks
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...   # Kanal → Edit → Integrations → Webhooks

WEBHOOK_URL=https://soar.example.internal/hook     # generischer JSON-Webhook (Zapier/Make/SOAR)
WEBHOOK_TOKEN=...                                  # optional → Authorization: Bearer

NTFY_TOPIC=wazuh-triage                            # https://ntfy.sh/wazuh-triage (oder eine vollständige URL)
NTFY_TOKEN=...                                     # optional, für ein geschütztes Topic

SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_SECURITY=starttls                             # starttls | ssl | none
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=wazuh-triage@example.org
SMTP_TO=secops@example.org,oncall@example.org
```

- **Telegram-Chat-ID:** Bot zur Gruppe hinzufügen (oder ihm eine Nachricht senden), `/start@<Ihr_Bot>` senden, dann
  `https://api.telegram.org/bot<token>/getUpdates` öffnen und `"chat":{"id":...}` entnehmen — Gruppen-IDs sind
  negativ (`-100…`). Sie senden Wazuh-Alarme bereits über das Notifications-Plugin des Dashboards an Telegram? Dann
  funktionieren dasselbe Bot-Token und dieselbe Chat-ID auch hier.
- **Teams:** Die alten Office 365-„Incoming Webhook“-Connectoren sind eingestellt; verwenden Sie die
  Workflows-Vorlage oben. Nachrichten kommen als Adaptive Cards mit Link zum Bericht an.
- **Slack:** App erstellen → *Incoming Webhooks* → zu einem Kanal hinzufügen → Webhook-URL kopieren. Nachrichten
  kommen als Block-Kit-Abschnitte mit Link zum Bericht an.
- **Discord:** Kanal → *Edit* → *Integrations* → *Webhooks* → *New Webhook*. Klartextnachrichten.
- **Generischer Webhook:** jeder Endpunkt, der einen JSON-Body akzeptiert (`{"title", "lines", "link", "text"}`);
  setzen Sie `WEBHOOK_TOKEN` für einen `Bearer`-Header.
- **ntfy:** Push an `https://ntfy.sh/<topic>` (oder selbst gehostet); der Titel wird zum Benachrichtigungstitel.
- Setups mit mehreren Umgebungen legen dieselben Schlüssel in einen `notify:`-Block, global oder pro Umgebung —
  siehe [docs/notifications.md](docs/notifications.md).

Nachrichten enthalten Umgebungsnamen, Fundtitel, Hostnamen und IPs — wählen Sie die Kanäle entsprechend.

## Regelentwürfe — Befehle oder Bereitstellung mit einem Klick

Jeder Regelentwurf in der Wissensdatenbank hat drei Schaltflächen:

- **Befehle** — ein Copy-Paste-Block für den Manager: Sicherung, Anhängen an `etc/rules/wdt_rules.xml`,
  `wazuh-analysisd -t` (stellt bei Fehler die Sicherung wieder her), Neustart, Prüfung, Zurückrollen. Funktioniert
  überall.
- **Genehmigen und bereitstellen** — pro Umgebung optional (`rule_deploy`). Schreibt den Entwurf über die
  Wazuh-API mit einem separaten Benutzer mit minimalen Rechten, validiert, startet den Manager oder Cluster neu,
  prüft, ob die Regel-IDs geladen sind, führt den beidseitigen Logtest des Entwurfs aus und **rollt bei jedem Fehler
  automatisch zurück**. Entwürfe, die Alarme stummschalten oder herabstufen, erfordern die Eingabe der Regel-IDs als
  zweite Bestätigung.
- **Aus Wazuh entfernen** — macht einen bereitgestellten Entwurf auf demselben Weg rückgängig.
- **Live prüfen / Dauerhaft machen** — sehen, ob die Regel seit ihrer Anwendung bei echten Ereignissen ausgelöst
  hat, und das Paket erhalten, das sie in Ihre eigene Regeldatei / Ihr Repository überführt (`promote:`
  konfigurieren).

Einrichtung und die exakten API-Berechtigungen: [docs/rule-deployment.md](docs/rule-deployment.md).

## Wissensdatenbank importieren / exportieren

Bringen Sie die Notizen, die Sie bereits führen (bekanntes Rauschen, Entscheidungen, Lehren), als YAML-Liste mit —
dasselbe Format wie [`config/seed/example.yaml`](config/seed/example.yaml):

```sh
python -m app.kb import noise.yaml -e prod --dry-run     # Vorschau
python -m app.kb import noise.yaml -e prod --update      # Neue hinzufügen, Geänderte aktualisieren (nach key oder Art+Titel)
kubectl exec -i deploy/wazuh-daily-triage -- python -m app.kb import - -e prod --update < noise.yaml
python -m app.kb export -e prod --kind baseline > baseline.yaml
```

Oder verwenden Sie **Import / Export** auf der Seite der Wissensdatenbank. Erneutes Ausführen erzeugt nie Duplikate.

## Kompatibilität

Die vollständige Matrix (Wazuh, Indexer, Python, Anbieter, Integrationen, bekannte Grenzen) steht in
[docs/compatibility.md](docs/compatibility.md). Kurz:

- Wazuh **4.x** (entwickelt und getestet mit 4.14) — All-in-One-, verteilte, Docker- und
  Kubernetes-Bereitstellungen.
- Wazuh Indexer / OpenSearch 2.x mit dem Standard-`wazuh-alerts-*`-Template. Indexmuster sind konfigurierbar.
- Die Wazuh-Server-API ist optional; ohne sie sind Agent-/Daemon-Zustand, Regelinformationen und Logtest
  deaktiviert.
- Python **3.11–3.13**; Basic Auth, private CA (`ca_file`) und Mutual TLS (`client_cert`/`client_key`) werden
  unterstützt.

## Sicherheitsmodell

> **Standardhaltung:** kein Schreibzugriff auf Wazuh, keine Shell, keine ausgehenden Anfragen des Modells. Alles,
> was die KI tun kann, ist eine Leseabfrage innerhalb konfigurierter Grenzen oder ein *Vorschlag*, der auf einen
> Menschen wartet. Der Produktionsstart verweigert Beispielpasswörter, ein fehlendes `APP_SECRET`, unsichere Cookies
> und deaktivierte TLS-Prüfung; jede zustandsändernde Anfrage wird in einem manipulationssicheren Prüfpfad
> protokolliert.

- **Standardmäßig schreibgeschützt gegenüber Wazuh.** Keine Active Response, keine Konfigurationsschreibvorgänge,
  keine Agentenbefehle. Die einzigen Indexschreibvorgänge gehen in die eigenen `daily-triage-*`-Indizes. Die
  optionale Regelbereitstellung verwendet einen separaten API-Benutzer, der nur benutzerdefinierte Regeldateien
  hochladen und den Manager neu starten kann; die Anwendung schreibt eine dedizierte Datei.
- **Prompt Injection.** Alarminhalte (URLs, `full_log`, User-Agents, Benutzernamen) werden vom Angreifer
  kontrolliert. Der Prompt markiert sie als Daten, und selbst ein getäuschtes Modell kann höchstens einen
  *Vorschlag* zur Wissensdatenbank hinzufügen, der nichts bewirkt, bis Sie ihn genehmigen. Feldnamen, Zeitfenster,
  Bucket-Anzahlen und Dokumentgrößen sind durch `query_guard` begrenzt, sodass eingeschleuster Text nicht zu einer
  teuren oder beliebigen Abfrage werden kann.
- **Minimale Rechte in der UI.** Zwei Rollen (Administrator, schreibgeschützter Betrachter) mit einer
  Berechtigungsmatrix und einer optionalen Umgebungs-Allow-List pro Rolle (`ADMIN_ENVS`, `VIEWER_ENVS`,
  `MCP_ENVS`), wenn Produktion und Staging eine Installation teilen. Prüfungen laufen serverseitig bei jeder Route,
  nicht im Template.
- **Prüfpfad.** Anmeldungen, Ablehnungen, Entscheidungen, Bereitstellungen und jede zustandsändernde Anfrage werden
  mit Akteur, Rolle, Umgebung, Ergebnis und einer SHA-256-Hashkette an `logs/audit.jsonl` angehängt — Manipulation
  bricht die Kette.
- **Regelbereitstellung schlägt geschlossen fehl.** Validierung, Neustart und Logtest werden verifiziert; eine
  fehlgeschlagene Erwartung *oder* ein nicht reproduzierbares Beispiel rollt die Änderung zurück, und ein
  fehlgeschlagener Rollback wird als kritisch protokolliert.
- **Daten verlassen Ihr Netzwerk.** Mit einem gehosteten LLM werden Alarmzusammenfassungen und Beispiel-Logzeilen an
  diesen Anbieter gesendet. Für regulierte Daten verwenden Sie ein lokales Modell oder `redact: true` (maskiert
  E-Mails, Passwörter, Token, Kartennummern; IP-Adressen bleiben für die Analyse erhalten; kein vollständiges DLP).
- **Web-UI.** Passwort + signiertes `HttpOnly`/`SameSite=Strict`-Cookie, Login-Drosselung, strikte CSP (keine
  Inline-Skripte), Modellausgabe als Markdown mit deaktiviertem HTML gerendert. Ein optionales schreibgeschütztes
  `VIEWER_PASSWORD` erlaubt einem Team, alles zu sehen, ohne etwas zu ändern. Der Container läuft als Nicht-root mit
  schreibgeschütztem Dateisystem und ohne Capabilities. Betreiben Sie ihn hinter TLS; mit einem SSO-Proxy setzen Sie
  `AUTH_DISABLED=true`.
- **Betrieb.** `/metrics` (Administrator-Sitzung oder `METRICS_TOKEN`) liefert Lauf-, Fehler-, Dauer-, Token- und
  Bereitstellungszähler; `/healthz` ist die Liveness- und `/readyz` die Readiness-Probe (bewusst ohne Indexer-Aufruf,
  damit ein Ausfall nicht die UI entfernt, die ihn erklärt); jede Logzeile und jeder Prüfdatensatz trägt eine
  `X-Request-ID`.

Melden Sie Schwachstellen privat — siehe [SECURITY.md](SECURITY.md). Bewusste Ausnahmen sind in
[docs/security-exceptions.md](docs/security-exceptions.md) aufgeführt.

## Architektur

```
          ┌──────────────── wazuh-daily-triage (ein Container) ─────────────────┐
Zeitplan  │ Collector ──► deterministische Zusammenfassung + Zustandsflags       │
 / Button │      │                                                               │
          │      ▼                                                               │
          │ Agent-Schleife ◄──► LLM (Anthropic / OpenAI-kompatibel)              │
          │   Werkzeuge: search · aggregate · timeline · ip_profile · correlate ·│
          │   vulns · agent · rule · logtest · validate_rule_xml · propose        │
          │      │                                                               │
          │      ▼                                                               │
          │ submit_report ──► daily-triage-runs ──► notify (Mail/Telegram/Teams/Slack/Discord/ntfy/Webhook) │
          │ Web-UI ◄──► daily-triage-runs / -knowledge                           │
          │ Genehmigen & bereitstellen (optional, separater API-Benutzer) ──► etc/rules/wdt_rules │
          └───────────┬──────────────────────────────┬───────────────────────────┘
                      │ HTTPS 9200                   │ HTTPS 55000
               Wazuh Indexer                  Wazuh Server-API
```

Python 3.12, FastAPI, Jinja2, httpx. Keine Anbieter-SDKs, kein Frontend-Build-Schritt. Modulkarte,
Anfragefluss und Erweiterungspunkte: [docs/architecture.md](docs/architecture.md).

## Entwicklung

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
pytest --cov=app --cov-report=term-missing     # was CI hochlädt
ruff check .
WDT_DEMO=true APP_PASSWORD=x uvicorn app.main:app --reload
```

`app/demo.py` enthält eine kleine OpenSearch-Abfrage-Engine und synthetische Daten, sodass Collector und Werkzeuge
ohne Cluster getestet werden. Eine UI-Sprache hinzufügen = ein Wörterbuch in `app/i18n.py` hinzufügen.

### Selbst messen

In diesem README stehen keine Marketingzahlen: Eine Recall-Zahl aus den Alarmen anderer sagt wenig über Ihre aus. Das
Repository liefert stattdessen das Messinstrument — `python -m app.eval` spielt Tage nach, die Sie selbst geprüft
haben, und bewertet die KI gegen Ihre Schlussfolgerungen:

```sh
python -m app.eval config/eval/demo.yaml               # Demo-Fälle, kein Wazuh nötig
python -m app.eval cases.yaml --repeat 3 --out res.json
```

Pro Fall meldet es **Recall** (erwartete Elemente gefunden), **verpasste** Elemente, **Rauschverstöße** (bekanntes
Rauschen als Vorfall gemeldet), Funde, Werkzeugschritte, Token und Laufzeit — sodass eine Änderung an Prompt, Modell
oder Schwellenwert eine gemessene Entscheidung ist. Schreiben Sie eigene Fälle aus echten Tagen (`docs/eval.md`);
drei bis fünf reichen, um eine Regression zu erkennen. CI führt die Tests aus, nicht die Evaluation (sie braucht ein
Modell und Ihre Daten).

## Roadmap

Siehe [ROADMAP.md](ROADMAP.md) — die Prioritätenliste umfasst signierte Image-Releases (eine SBOM wird bereits pro
Build erzeugt), ServiceNow/GitHub-Ticketing, Decoder-Entwürfe, eingebettete Diagramme und weitere Sprachen.

## Danksagungen

- [Wazuh — Threat hunting with agentic AI](https://wazuh.com/blog/threat-hunting-with-agentic-ai/) (Rollen mit
  minimalen Rechten, Korrelationsfenster)
- [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server),
  [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh)

## Lizenz

Copyright © 2026 Rüstem Duru. Lizenziert unter der **GNU Affero General Public License v3.0** — siehe
[LICENSE](LICENSE) und [NOTICE](NOTICE). Wenn Sie eine modifizierte Version für Benutzer über ein Netzwerk
betreiben, müssen Sie ihnen den Quellcode anbieten (`SOURCE_URL` auf Ihren Fork setzen).

Wazuh ist eine Marke von Wazuh, Inc. Dieses Projekt ist unabhängig und nicht mit Wazuh, Inc. verbunden.
