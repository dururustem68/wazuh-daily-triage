# Wazuh Daily Triage

**Revisión diaria asistida por IA para [Wazuh](https://wazuh.com) SIEM.** Cada mañana comprueba que tu SIEM esté
realmente vivo, separa el riesgo real del ruido conocido, escribe un breve informe de diagnóstico de vuelta en tu
Wazuh Indexer, te pregunta solo lo que requiere una decisión humana — y recuerda tus respuestas la próxima vez.

Trae tu propia IA: Anthropic, OpenAI, Azure OpenAI o cualquier endpoint compatible con OpenAI (Ollama, vLLM,
LM Studio, LiteLLM). Un contenedor Docker, de solo lectura hacia Wazuh por defecto. Las alertas críticas y los
resúmenes de ejecución llegan por correo, Telegram, Microsoft Teams, Slack, Discord, ntfy o un webhook genérico.

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Español](README.es.md) · [Proveedores de IA](docs/providers.md) · [Notificaciones](docs/notifications.md) · [Permisos y red](docs/permissions.md) · [Despliegue de reglas](docs/rule-deployment.md) · [Arquitectura](docs/architecture.md) · [Compatibilidad](docs/compatibility.md) · [Contribuir](CONTRIBUTING.md) · [Seguridad](SECURITY.md)

![Informe](docs/screenshot-report.png)

| Bandeja de recomendaciones | Base de conocimiento y borradores de reglas |
|---|---|
| ![Bandeja](docs/screenshot-inbox.png) | ![Base de conocimiento](docs/screenshot-knowledge.png) |

<img src="docs/screenshot-audit-pdf.png" alt="Informe de auditoría mensual (PDF)" width="430">

## Por qué

Si tus mañanas empiezan con la misma rutina de Wazuh — *¿fluyen los datos, están conectados los agentes, qué hay en
nivel 7+, qué parte es el ruido habitual, qué parte es real* — esta herramienta hace el trabajo pesado y te llama
solo donde hace falta una decisión. Codifica hábitos de revisión ganados con esfuerzo: salud antes que alertas,
distribuciones en vez de medias, «mismo recuento en todos los agentes = evento de feed», «cero no significa que la
regla funcione», bajar el nivel en vez de silenciar.

## Funciones

- **Ejecuciones programadas** por entorno (una o varias veces al día + días de la semana). La ventana es «desde la
  última ejecución correcta», así que el lunes por la mañana cubre el fin de semana.
- **Recogida determinista primero** — independiente de la IA: hora de la última alerta y horas vacías (puntos
  ciegos), salud y disco del indexer, daemons del manager, agentes inactivos, errores de `ossec.log`, distribución
  por niveles, grupos de nivel alto (regla × agente × primera/última vez × IP de origen × muestra), comparación con
  la ventana anterior, IDs de regla **vistos por primera vez en 14 días**, reglas vigiladas, resumen de
  vulnerabilidades.
- **Diagnóstico por IA** — el modelo lee el resumen más tu base de conocimiento, profundiza con herramientas de solo
  lectura (distribución temporal, perfil de IP, correlación ±30 min, logtest, definiciones de reglas) y entrega un
  informe estructurado: *incidente real, investigar, hueco de detección, falso positivo, aumento de línea base…*
  Redacta reglas de Wazuh y las comprueba en busca de errores XML, trampas de OS_Regex y colisiones de ID.
- **Borradores de reglas listos para enviar** — cada borrador incluye comandos para copiar y pegar en el manager
  (copia de seguridad, `wazuh-analysisd -t`, reinicio, reversión). Opcionalmente, **Aprobar y desplegar** escribe el
  borrador mediante la API de Wazuh en un archivo de reglas dedicado, valida, reinicia, comprueba que se cargó,
  ejecuta un logtest bidireccional y revierte ante cualquier fallo; los borradores que silencian o bajan alertas
  requieren una segunda confirmación escribiendo los IDs de regla
  ([docs/rule-deployment.md](docs/rule-deployment.md)). Desactivado por defecto.
- **Te pregunta** — «¿Este inicio de sesión SSH fue tuyo?» Tu respuesta va a la base de conocimiento y es contexto
  para la siguiente ejecución.
- **Base de conocimiento** — ruido conocido, decisiones («no sugieras X»), asuntos abiertos, lecciones, peticiones
  «mira esto mañana». Las propuestas de la IA **no tienen efecto hasta que las apruebas**. Trae tus notas
  existentes con importación/exportación YAML (UI o `python -m app.kb`), repetible sin duplicados.
- **Bandeja de recomendaciones** — hallazgos de uno en uno, deduplicados entre ejecuciones; una decisión resuelve
  todas las apariciones. Los hallazgos que requieren una revisión en un servidor incluyen comandos exactos de solo
  lectura, y un clic copia el hallazgo con esos comandos para pegar la salida donde trabajes.
- **Notificaciones por correo, Telegram, Microsoft Teams, Slack, Discord, ntfy o webhook genérico** — situaciones
  críticas (SIEM en silencio, indexer en rojo, incidentes reales) sin repetir el mismo elemento en cada ejecución, un
  resumen corto opcional después de cada ejecución y los despliegues de reglas
  ([docs/notifications.md](docs/notifications.md)).
- **Verificación en vivo** — una regla desplegada, aprobada o promovida se comprueba contra eventos reales después
  de cada ejecución: «confirmada en vivo 12× (última …)» o «no vista en 5 días». `logtest passed` no es prueba; un
  evento real sí.
- **Hacer permanente** — para un borrador probado, un paquete de promoción para *tu* gestión de configuración: el
  bloque de regla con procedencia, un script (copia → añadir → `wazuh-analysisd -t` en el manager en ejecución →
  desplegar con `kubectl apply -k` o reiniciar → comprobar que se cargó) y un borrador de § para tu catálogo de
  alertas.
- **Saturación del canal de correo** — con `mail:` configurado, cada ejecución muestra las horas en que una avalancha
  superó `email_maxperhour` y las demás reglas que se dispararon en esas horas y puede que nunca se enviaran.
- **Cobertura y SLA de vulnerabilidades** — agentes por estado/versión/nodo, agentes esperados pero ausentes de una
  lista de inventario y vulnerabilidades activas abiertas más tiempo que el SLA por severidad.
- **Informe de auditoría mensual** — volumen de alertas, ejecuciones, hallazgos y tus decisiones, cambios de reglas
  (quién, cuándo, qué se bajó), caídas del SIEM según la comprobación de liveness, cobertura y SLA de
  vulnerabilidades. Determinista (sin IA), descargable en PDF o Markdown — evidencia para revisiones ISO 27001 /
  ISMS.
- **Anomalías sin IA** — cada ejecución compara los recuentos regla × agente con los 14 días anteriores: picos
  (puntuación z) y reglas que se disparan en un agente por primera vez; la IA empieza desde ahí.
- **Más allá de Wazuh (opcional)** — herramientas de solo lectura de Prometheus, Loki y Kubernetes (pods, reinicios,
  OOM kills, presión de nodo, eventos, logs de pod; nunca secretos) para comprobar la causa de una alerta en vez de
  adivinarla ([docs/sources.md](docs/sources.md)).
- **Borradores de registro de incidente** — un clic en un hallazgo: la IA reúne la evidencia y rellena tu plantilla
  de incidente (cronología, causa raíz, impacto, consultas de evidencia, acciones); edítalo, descárgalo o ábrelo como
  ticket de Zammad o Jira.
- **Servidor MCP** — las mismas herramientas de solo lectura para Claude Desktop o cualquier cliente MCP, para
  investigar con datos en vivo desde tu propio asistente ([docs/mcp.md](docs/mcp.md)).
- **Evaluación** — `python -m app.eval` reproduce días que revisaste tú mismo y puntúa a la IA (recall, ruido
  notificado como incidente, tokens): compara modelos y prompts con números ([docs/eval.md](docs/eval.md)).
- **Salida lista para copiar** — cada hallazgo y cada pregunta tiene un botón de copiar (texto plano: evidencia,
  recomendación, comandos) para tickets, correo o una terminal.
- **Guardado en el propio Wazuh** — índices `daily-triage-runs` y `daily-triage-knowledge` en el indexer de cada
  entorno. Sin base de datos adicional. `run_retention_days` opcional elimina ejecuciones antiguas; la base de
  conocimiento nunca se borra.
- **Multi-entorno, multi-idioma** (inglés, turco, español, alemán), sustitución de IA por entorno (p. ej. un modelo
  local para datos regulados), prueba de conexión en la UI y en la CLI.

## Inicio rápido

### 1. Probar la demo (sin Wazuh)

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git && cd wazuh-daily-triage
cp .env.example .env
sed -i 's/^WDT_DEMO=.*/WDT_DEMO=true/; s/^LLM_PROVIDER=.*/LLM_PROVIDER=mock/; s/^APP_LANGUAGE=.*/APP_LANGUAGE=es/' .env
docker compose up -d --build
# abre http://127.0.0.1:8080 — contraseña: APP_PASSWORD de .env
```

La demo usa datos sintéticos (fuerza bruta Basic-Auth de Jenkins, intentos SSH, un agente desconectado, una oleada
de vulnerabilidades tras una actualización…). `mock` no hace análisis real; configura las variables `LLM_*` para
probar un modelo real con los mismos datos.

### 2. Conectar tu Wazuh — un entorno, sin YAML

Crea las cuentas de solo lectura descritas en **[docs/permissions.md](docs/permissions.md)** y luego en `.env`:

```sh
WDT_DEMO=false
LLM_PROVIDER=anthropic          # o openai
LLM_MODEL=<id del modelo de tu proveedor>
LLM_API_KEY=<tu clave>
WAZUH_INDEXER_URL=https://wazuh-indexer.example.internal:9200
WAZUH_INDEXER_USER=daily-triage
WAZUH_INDEXER_PASSWORD=...
WAZUH_API_URL=https://wazuh-manager.example.internal:55000   # opcional
WAZUH_API_USER=daily-triage
WAZUH_API_PASSWORD=...
WAZUH_CA_FILE=/app/config/certs/root-ca.pem                   # copia tu CA en ./config/certs/
```

```sh
docker compose up -d
docker compose exec triage python -m app.check    # o «Probar conexiones» en la página del entorno
```

### 3. Varios entornos

```sh
cp config/environments.example.yaml config/environments.yaml
vi config/environments.yaml        # un bloque por Wazuh; secretos como ${VARS} desde .env
vi config/context/<entorno>.md     # unas líneas describiendo el entorno
```

`config/environments.yaml`, `config/context/*`, `config/seed/*`, `config/certs/` y `.env` están excluidos de Git.

### Kubernetes

Un **[Helm chart](deploy/helm/wazuh-daily-triage)** y una base kustomize, un overlay de ejemplo y componentes
opcionales en **[deploy/kubernetes](deploy/kubernetes/README.md)** — una réplica, sin root, sistema de archivos de
solo lectura, sin PVC (el estado vive en el Wazuh Indexer). Componentes: `networkpolicy`, `ingress-nginx` (TLS,
cert-manager, opción oauth2-proxy) e `ingress-traefik-authentik` (SSO).

## Proveedores de IA

Trae tu propia clave. Configuración completa para cada proveedor, incluidos nombres de modelo y particularidades de
parámetros: **[docs/providers.md](docs/providers.md)**.

| Proveedor | `LLM_PROVIDER` | `LLM_BASE_URL` | `LLM_MODEL` de ejemplo |
|---|---|---|---|
| Claude (Anthropic) | `anthropic` | — | `claude-sonnet-5-5` |
| OpenAI | `openai` | `https://api.openai.com/v1` | `gpt-6.1-sol` ¹ |
| Google Gemini | `openai` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-3.8-flash` |
| DeepSeek | `openai` | `https://api.deepseek.com` | `deepseek-flash` |
| Azure OpenAI | `openai` | URL completa del despliegue con `?api-version=` | tu despliegue |
| Ollama / vLLM / LM Studio / LiteLLM | `openai` | p. ej. `http://ollama:11434/v1` | p. ej. `qwen3:14b` |

¹ Los modelos de razonamiento de OpenAI también necesitan `LLM_TOKEN_PARAM=max_completion_tokens` y
`LLM_TEMPERATURE=none`.

El modelo debe admitir llamadas a herramientas (function calling). Cada entorno puede sustituir el modelo (bloque
`llm:`) — p. ej. un modelo local para un entorno cuyos datos no deben salir de tu red. `max_tool_steps` limita el
coste por ejecución.

## Notificaciones — correo, Telegram, Teams, Slack, Discord, ntfy, webhook

| Cuándo | Ajuste (por defecto) |
|---|---|
| SIEM en silencio, indexer en rojo, daemon del manager caído, disco del indexer ≥ 90 % | `on_critical_flags: true` |
| Hallazgo etiquetado *incidente real* / severidad *crítica* | `on_real_incident: true`, `on_critical_findings: true` |
| La propia ejecución falló | `on_run_error: false` |
| Resumen corto después de **cada** ejecución (salud, recuentos, recomendaciones pendientes) | `on_run_summary: false` |
| Se desplegó, revirtió o eliminó un borrador de regla | `on_rule_deploy: true` |
| **Comprobación de liveness cada 10 min** (sin IA): indexer/API inaccesible, daemon caído, SIEM en silencio, disco ≥ 90 % — problema, recordatorio, recuperado | `on_liveness: true`, `liveness.interval_minutes` |

El mismo elemento crítico no se repite dentro de `repeat_hours` (24). Un canal está activo en cuanto sus campos están
configurados; **Probar notificaciones** en la página del entorno los comprueba todos.

```sh
# .env — cualquier combinación de canales
NOTIFY_UI_URL=https://triage.example.internal      # enlace en los mensajes
NOTIFY_ON_RUN_SUMMARY=true

TELEGRAM_BOT_TOKEN=123456789:AA...                 # @BotFather → /newbot
TELEGRAM_CHAT_ID=-1001234567890                    # ver abajo

TEAMS_WEBHOOK_URL=https://...                      # canal → Workflows → "Post to a channel when a webhook request is received"

SLACK_WEBHOOK_URL=https://hooks.slack.com/...      # Your Apps → Incoming Webhooks
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...   # canal → Edit → Integrations → Webhooks

WEBHOOK_URL=https://soar.example.internal/hook     # webhook JSON genérico (Zapier/Make/SOAR)
WEBHOOK_TOKEN=...                                  # opcional → Authorization: Bearer

NTFY_TOPIC=wazuh-triage                            # https://ntfy.sh/wazuh-triage (o una URL completa)
NTFY_TOKEN=...                                     # opcional, para un tema protegido

SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_SECURITY=starttls                             # starttls | ssl | none
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=wazuh-triage@example.org
SMTP_TO=secops@example.org,oncall@example.org
```

- **Chat id de Telegram:** añade el bot al grupo (o envíale un mensaje), envía `/start@<tu_bot>`, luego abre
  `https://api.telegram.org/bot<token>/getUpdates` y toma `"chat":{"id":...}` — los ids de grupo son negativos
  (`-100…`). ¿Ya envías alertas de Wazuh a Telegram con el plugin Notifications del Dashboard? El mismo token de bot
  y chat id funcionan aquí.
- **Teams:** los antiguos conectores «Incoming Webhook» de Office 365 están retirados; usa la plantilla de Workflows
  de arriba. Los mensajes llegan como Adaptive Cards con un enlace al informe.
- **Slack:** crea una app → *Incoming Webhooks* → añádela a un canal → copia la Webhook URL. Los mensajes llegan como
  secciones de block-kit con un enlace al informe.
- **Discord:** canal → *Edit* → *Integrations* → *Webhooks* → *New Webhook*. Mensajes de texto plano.
- **Webhook genérico:** cualquier endpoint que acepte un cuerpo JSON (`{"title", "lines", "link", "text"}`);
  configura `WEBHOOK_TOKEN` para una cabecera `Bearer`.
- **ntfy:** push a `https://ntfy.sh/<topic>` (o autohospedado); el título se convierte en el título de la
  notificación.
- Las instalaciones multi-entorno ponen las mismas claves en un bloque `notify:`, global o por entorno — consulta
  [docs/notifications.md](docs/notifications.md).

Los mensajes contienen nombres de entorno, títulos de hallazgos, nombres de host e IPs — elige los canales en
consecuencia.

## Borradores de reglas — comandos o despliegue con un clic

Cada borrador de regla en la base de conocimiento tiene tres botones:

- **Comandos** — un bloque para copiar y pegar en el manager: copia de seguridad, añadir a
  `etc/rules/wdt_rules.xml`, `wazuh-analysisd -t` (restaura la copia si falla), reinicio, verificación, reversión.
  Funciona en todas partes.
- **Aprobar y desplegar** — opcional por entorno (`rule_deploy`). Escribe el borrador mediante la API de Wazuh con un
  usuario separado de mínimos privilegios, valida, reinicia el manager o el clúster, comprueba que los IDs de regla
  están cargados, ejecuta el logtest bidireccional del borrador y **revierte automáticamente** ante cualquier fallo.
  Los borradores que silencian o bajan alertas requieren escribir los IDs de regla como segunda confirmación.
- **Quitar de Wazuh** — deshace un borrador desplegado de la misma manera.
- **Comprobar en vivo / Hacer permanente** — ver si la regla se disparó con eventos reales desde que se aplicó, y
  obtener el paquete que la traslada a tu propio archivo de reglas / repositorio (configura `promote:`).

Configuración y los permisos exactos de la API: [docs/rule-deployment.md](docs/rule-deployment.md).

## Importar / exportar la base de conocimiento

Trae las notas que ya mantienes (ruido conocido, decisiones, lecciones) como una lista YAML — el mismo formato que
[`config/seed/example.yaml`](config/seed/example.yaml):

```sh
python -m app.kb import noise.yaml -e prod --dry-run     # vista previa
python -m app.kb import noise.yaml -e prod --update      # añade nuevas, actualiza cambiadas (por key o tipo+título)
kubectl exec -i deploy/wazuh-daily-triage -- python -m app.kb import - -e prod --update < noise.yaml
python -m app.kb export -e prod --kind baseline > baseline.yaml
```

O usa **Importar / exportar** en la página de la base de conocimiento. Volver a ejecutarlo nunca crea duplicados.

## Compatibilidad

Consulta [docs/compatibility.md](docs/compatibility.md) para la matriz completa (Wazuh, indexer, Python, proveedores,
integraciones, límites conocidos). En resumen:

- Wazuh **4.x** (desarrollado y probado con 4.14) — despliegues all-in-one, distribuidos, Docker y Kubernetes.
- Wazuh Indexer / OpenSearch 2.x con la plantilla estándar `wazuh-alerts-*`. Los patrones de índice son
  configurables.
- La API del servidor Wazuh es opcional; sin ella se desactivan la salud de agentes/daemons, la información de
  reglas y el logtest.
- Python **3.11–3.13**; se admiten basic auth, CA privada (`ca_file`) y TLS mutuo
  (`client_cert`/`client_key`).

## Modelo de seguridad

> **Postura por defecto:** sin acceso de escritura a Wazuh, sin shell, sin peticiones salientes del modelo. Todo lo
> que la IA puede hacer es una consulta de lectura dentro de límites configurados, o una *propuesta* que espera a un
> humano. El arranque en producción rechaza contraseñas de ejemplo, un `APP_SECRET` ausente, cookies inseguras y la
> verificación TLS desactivada; cada petición que cambia estado se escribe en un rastro de auditoría a prueba de
> manipulación.

- **Solo lectura hacia Wazuh por defecto.** Sin active response, sin escrituras de configuración, sin comandos a
  agentes. Las únicas escrituras de índice van a sus propios índices `daily-triage-*`. El despliegue opcional de
  reglas usa un usuario de API separado que solo puede subir archivos de reglas personalizadas y reiniciar el
  manager; la aplicación escribe un archivo dedicado.
- **Inyección de prompt.** El contenido de las alertas (URLs, `full_log`, user agents, nombres de usuario) está
  controlado por el atacante. El prompt lo marca como datos, y aun un modelo engañado puede como mucho añadir una
  *propuesta* a la base de conocimiento, que no hace nada hasta que la apruebes. Los nombres de campo, ventanas
  temporales, recuentos de buckets y tamaños de documento están limitados por `query_guard`, así que el texto
  inyectado no puede convertirse en una consulta cara o arbitraria.
- **Mínimo privilegio en la UI.** Dos roles (administrador, visor de solo lectura) con una matriz de permisos, y una
  lista de entornos permitidos opcional por rol (`ADMIN_ENVS`, `VIEWER_ENVS`, `MCP_ENVS`) cuando producción y staging
  comparten una instalación. Las comprobaciones se ejecutan en el servidor en cada ruta, no en la plantilla.
- **Rastro de auditoría.** Inicios de sesión, denegaciones, decisiones, despliegues y cada petición que cambia estado
  se añaden a `logs/audit.jsonl` con actor, rol, entorno, resultado y una cadena hash SHA-256 — manipularla rompe la
  cadena.
- **El despliegue de reglas falla cerrado.** Se verifican validación, reinicio y logtest; una expectativa fallida *o*
  una muestra que no se puede reproducir revierte el cambio, y una reversión fallida se registra como crítica.
- **Datos que salen de tu red.** Con un LLM alojado, los resúmenes de alertas y las líneas de log de muestra se
  envían a ese proveedor. Para datos regulados usa un modelo local o `redact: true` (enmascara correos, contraseñas,
  tokens, números de tarjeta; las IPs se mantienen para el análisis; no es un DLP completo).
- **UI web.** Contraseña + cookie firmada `HttpOnly`/`SameSite=Strict`, limitación de intentos de login, CSP estricta
  (sin scripts inline), salida del modelo renderizada como markdown con HTML desactivado. Un `VIEWER_PASSWORD`
  opcional de solo lectura permite a un equipo verlo todo sin cambiar nada. El contenedor se ejecuta sin root con
  sistema de archivos de solo lectura y todas las capacidades eliminadas. Ponlo detrás de TLS; con un proxy SSO
  configura `AUTH_DISABLED=true`.
- **Operaciones.** `/metrics` (sesión de administrador o `METRICS_TOKEN`) expone contadores de ejecuciones, errores,
  duración, tokens y despliegues; `/healthz` es la sonda de vitalidad y `/readyz` la de disponibilidad (a propósito
  sin llamada al Indexer, para que una caída no retire la UI que la explica); cada línea de log y registro de
  auditoría lleva un `X-Request-ID`.

Informa de vulnerabilidades en privado — consulta [SECURITY.md](SECURITY.md). Las excepciones deliberadas se listan
en [docs/security-exceptions.md](docs/security-exceptions.md).

## Arquitectura

```
          ┌──────────────── wazuh-daily-triage (un contenedor) ─────────────────┐
programa  │ Collector ──► resumen determinista + flags de salud                  │
 / botón  │      │                                                               │
          │      ▼                                                               │
          │ Bucle del agente ◄──► LLM (Anthropic / compatible con OpenAI)        │
          │   herramientas: search · aggregate · timeline · ip_profile · correlate ·│
          │   vulns · agent · rule · logtest · validate_rule_xml · propose        │
          │      │                                                               │
          │      ▼                                                               │
          │ submit_report ──► daily-triage-runs ──► notify (correo/Telegram/Teams/Slack/Discord/ntfy/webhook) │
          │ UI web ◄──► daily-triage-runs / -knowledge                           │
          │ Aprobar y desplegar (opcional, usuario API separado) ──► etc/rules/wdt_rules │
          └───────────┬──────────────────────────────┬───────────────────────────┘
                      │ HTTPS 9200                   │ HTTPS 55000
               Wazuh Indexer                  API del servidor Wazuh
```

Python 3.12, FastAPI, Jinja2, httpx. Sin SDKs de proveedores, sin paso de build de frontend. Mapa de módulos, flujo
de peticiones y puntos de extensión: [docs/architecture.md](docs/architecture.md).

## Desarrollo

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
pytest --cov=app --cov-report=term-missing     # lo que sube CI
ruff check .
WDT_DEMO=true APP_PASSWORD=x uvicorn app.main:app --reload
```

`app/demo.py` contiene un pequeño motor de consultas OpenSearch y datos sintéticos, así que el collector y las
herramientas se prueban sin clúster. Añadir un idioma a la UI = añadir un diccionario a `app/i18n.py`.

### Medirlo tú mismo

En este README no hay cifras de marketing: un dato de recall de las alertas de otro dice poco sobre las tuyas. El
repositorio incluye el instrumento — `python -m app.eval` reproduce días que revisaste tú mismo y puntúa a la IA
contra lo que concluiste:

```sh
python -m app.eval config/eval/demo.yaml               # casos de demo, sin Wazuh
python -m app.eval cases.yaml --repeat 3 --out res.json
```

Por caso informa de **recall** (elementos esperados encontrados), elementos **perdidos**, **violaciones de ruido**
(ruido conocido notificado como incidente), hallazgos, pasos de herramientas, tokens y tiempo — así un cambio de
prompt, modelo o umbral es una decisión medida. Escribe tus propios casos a partir de días reales (`docs/eval.md`);
tres a cinco bastan para detectar una regresión. CI ejecuta la suite, no la evaluación (necesita un modelo y tus
datos).

## Hoja de ruta

Consulta [ROADMAP.md](ROADMAP.md) — la lista de prioridades incluye releases de imagen firmados (ya se genera un SBOM
por build), ticketing ServiceNow/GitHub, borradores de decodificadores, gráficos integrados y más idiomas.

## Agradecimientos

- [Wazuh — Threat hunting with agentic AI](https://wazuh.com/blog/threat-hunting-with-agentic-ai/) (roles de mínimo
  privilegio, ventana de correlación)
- [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server),
  [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh)

## Licencia

Copyright © 2026 Rüstem Duru. Licenciado bajo la **GNU Affero General Public License v3.0** — consulta
[LICENSE](LICENSE) y [NOTICE](NOTICE). Si ejecutas una versión modificada para usuarios a través de una red, debes
ofrecerles su código fuente (configura `SOURCE_URL` con tu fork).

Wazuh es una marca registrada de Wazuh, Inc. Este proyecto es independiente y no está afiliado a Wazuh, Inc.
