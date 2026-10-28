# Yapılandırma

İki katman, tek kural: **parolalar ve anahtarlar ortamda, yapı YAML'da**.

| Katman | Dosya | İçerik |
|---|---|---|
| Ortam | `.env` (Docker), Kubernetes Secret/ConfigMap, kabuk değişkenleri | parolalar, API anahtarları, arayüz/kimlik anahtarları, bildirim kanalları |
| Yapı | `config/environments.yaml` | hangi Wazuh ortamları var, zamanlamalar, eşikler, ortam bazlı seçenekler |

YAML içindeki `${DEGISKEN}` ve `${DEGISKEN:-varsayilan}` yer tutucuları açılışta ortamdan genişletilir; boş
değişken de varsayılana döner (`${PROD_INDEXER_PASSWORD}` değersizse boş string olur, `${TZ:-UTC}` ise `UTC`).

## Hangi yapılandırma kullanılır?

```
WDT_CONFIG tanımlı mı?        → o dosya
config/environments.yaml var? → YAML modu: tüm ortamlar YAML'dan
aksi halde                    → WAZUH_* değişkenleriyle tek ortam modu
```

- Docker `WDT_CONFIG=/app/config/environments.yaml` ayarlar ve `./config` dizinini `/app/config`'e bağlar.
- **YAML modunda** `WAZUH_*` tek-ortam değişkenleri yok sayılır (isterseniz YAML içinde `${WAZUH_...}` olarak
  kullanabilirsiniz).
- **Tek ortam modunda** `WAZUH_*`, `SCHEDULE_*`, `HIGH_LEVEL`, `WINDOW_MIN_HOURS`, `REDACT`, `INVENTORY`,
  `LIVENESS_*` ve `RULE_DEPLOY_*` değişkenleri `default` kimlikli tek ortamı kurar.
- `.env`, `config/environments.yaml`, `config/certs/`, `config/context/*` ve `config/seed/*` git tarafından
  yok sayılır.

## Ortam değişkenleri

### Web arayüzü, kimlik doğrulama, süreç

| Değişken | Varsayılan | Anlam |
|---|---|---|
| `ENVIRONMENT` | *(boş)* | `production` (veya `prod`, `live`) ölümcül açılış kontrollerini açar; diğer değerler laboratuvar sayılır. |
| `APP_PASSWORD` | *(boş)* | Admin parolası. Üretimde `AUTH_DISABLED=true` değilse zorunlu. |
| `VIEWER_PASSWORD` | *(boş)* | İsteğe bağlı salt okunur parola; `APP_PASSWORD`'dan farklı olmalı. [Görüntüleyici modu](Viewer-Mode-TR). |
| `APP_SECRET` | *(rastgele)* | Oturum imzalama anahtarı (`openssl rand -hex 32`). Boşsa her yeniden başlatma oturumları düşürür. |
| `AUTH_DISABLED` | `false` | Uygulama girişi yerine SSO vekiline güven (`true`/`1`/`yes`). [SSO](SSO-Proxy-Auth-TR). |
| `USER_HEADER` | `X-authentik-username,X-Forwarded-User,Remote-User,X-Auth-Request-User` | Virgülle ayrılmış başlık adları; ilk dolu olan denetim kaydında aktör olur. |
| `COOKIE_SECURE` | `false` | Oturum çerezini `Secure` yapar; üretimde `true` olmalı. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` (Docker) | Uvicorn'un güvendiği vekil adresleri; asla `*`. |
| `APP_LANGUAGE` | `en` | Arayüz ve rapor dili: `en`, `tr`, `es`, `de`. |
| `TZ` | `UTC` | Zamanlama ve zaman damgaları için IANA saat dilimi; açılışta doğrulanır. |
| `SOURCE_URL` | proje deposu | Alt bilgi bağlantısı (AGPL-3.0 §13 — kodu değiştirdiyseniz kendi fork'unuzu gösterin). |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `WDT_SCHEDULER` | `true` | `false` süreç içi zamanlayıcıyı kapatır (elle koşu ve arayüz çalışır). |
| `WDT_DEMO` | `false` | Demo modu: sentetik veri, `config/demo.yaml`, üretimde asla. |
| `WDT_CONFIG` | `config/environments.yaml` | YAML yapılandırma yolu. |

### Yetkilendirme, denetim, token'lar

| Değişken | Varsayılan | Anlam |
|---|---|---|
| `ADMIN_ENVS` | *(boş = tümü)* | Admin rolünün görebileceği ortam kimlikleri (virgüllü). |
| `VIEWER_ENVS` | *(boş = tümü)* | Görüntüleyici rolünün görebileceği ortamlar. |
| `MCP_ENVS` | *(boş = tümü)* | MCP istemcilerinin sorgulayabileceği ortamlar. |
| `AUDIT_LOG` | `true` | Eklemeli JSONL denetim kaydı; `false` yalnızca testler için. |
| `AUDIT_LOG_FILE` | `logs/audit.jsonl` | Denetim dosyası yolu. |
| `METRICS_TOKEN` | *(boş)* | `/metrics` için Bearer token; boşsa admin oturumu gerekir. |
| `MCP_TOKEN` | *(boş)* | `POST /mcp`'yi açar; yoksa uç nokta `404` döner. [MCP](MCP-TR). |

### Model (LLM)

| Değişken | Varsayılan | Anlam |
|---|---|---|
| `LLM_PROVIDER` | `anthropic` | `anthropic`, `openai` (OpenAI uyumlu her uç nokta) veya `mock`. |
| `LLM_MODEL` | *(boş)* | Sağlayıcının model kimliği. |
| `LLM_API_KEY` | *(boş)* | Kimlik doğrulaması olmayan yerel modelde gerekmez. |
| `LLM_BASE_URL` | *(boş)* | OpenAI uyumlu taban URL: OpenAI, Gemini, DeepSeek, Azure, Ollama, vLLM, LM Studio… |
| `LLM_MAX_TOKENS` | `4096` | Çıktı bütçesi; çok düşükse rapor kesilir. |
| `LLM_TEMPERATURE` | `0.2` | `none`/`default`/`off` değeri sağlayıcıya bırakır (reasoning modelleri). |
| `LLM_TOKEN_PARAM` | `max_tokens` | Yeni OpenAI modelleri için `max_completion_tokens`. |
| `LLM_REASONING_EFFORT` | *(boş)* | Sağlayıcıya özgü çaba alanı. |
| `LLM_EXTRA_BODY` | *(boş)* | Sağlayıcıya aynen geçirilen JSON nesnesi. |
| `LLM_MAX_RETRIES` | `4` | 429/5xx/aşırı yükte geri çekilmeli yeniden deneme. |
| `LLM_MAX_TOOL_STEPS` | `14` | Koşu başına araç çağrısı bütçesi (maliyet tavanı). |

### Bildirimler

| Değişken | Varsayılan | Anlam |
|---|---|---|
| `NOTIFY_ENABLED` | `true` | Ana anahtar. |
| `NOTIFY_UI_URL` | *(boş)* | Mesajlardaki bağlantı, ör. `https://triage.example.internal`. |
| `NOTIFY_REPEAT_HOURS` | `24` | Aynı kritik maddeyi bu süre içinde tekrar gönderme. |
| `NOTIFY_ON_RUN_SUMMARY` | `false` | Her koşudan sonra kısa özet (varsayılan: yalnızca kritik). |
| `NOTIFY_ON_RUN_ERROR` | `false` | Koşu hata verirse mesaj. |
| `NOTIFY_ON_RULE_DEPLOY` | `true` | Dağıtım/geri alma bildirimi. |
| `NOTIFY_ON_LIVENESS` | `true` | Canlılık sorunu ve düzelme bildirimi. |
| `LIVENESS_ENABLED` | `true` | Yapay zekâsız hızlı kontrol. |
| `LIVENESS_INTERVAL_MINUTES` | `10` | 2–120 dakika. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO`, `SMTP_VERIFY_TLS` | `587`, `starttls`, `true` | E-posta kanalı (`starttls`, `ssl`, `none`). |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | *(boş)* | Telegram. |
| `TEAMS_WEBHOOK_URL`, `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL` | *(boş)* | Webhook'lar. |
| `WEBHOOK_URL`, `WEBHOOK_TOKEN` | *(boş)* | Genel JSON webhook; token `Authorization: Bearer` olur. |
| `NTFY_TOPIC`, `NTFY_TOKEN` | *(boş)* | ntfy push. |

Bir kanal, alanları dolu olduğunda açıktır. Ayrıntılar: [docs/notifications.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/notifications.md).

### Tek ortam (`WAZUH_*`)

| Değişken | Varsayılan | Anlam |
|---|---|---|
| `WAZUH_ENV_ID` | `default` | URL'lerde kullanılan küçük harfli kimlik (`a-z0-9`, `-`, `_`). |
| `WAZUH_ENV_NAME` | `Wazuh` | Görünen ad. |
| `WAZUH_INDEXER_URL` | *(zorunlu)* | `https://host:9200`. |
| `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` | *(boş)* | Salt okunur indexer hesabı. |
| `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD` | *(boş)* | İsteğe bağlı Wazuh API. |
| `WAZUH_VERIFY_TLS` | `true` | Doğrulamayı kapatmak yerine `WAZUH_CA_FILE` kullanın. |
| `WAZUH_CA_FILE` | *(boş)* | Konteyner içindeki özel CA yolu (`/app/config/certs/root-ca.pem`). |
| `WAZUH_ALERTS_INDEX` | `wazuh-alerts-4.x-*` | Alarm indeks deseni. |
| `SCHEDULE_ENABLED` | `true` | Zamanlanmış koşular. |
| `SCHEDULE_TIME` | `07:30` | Tek saat veya virgüllü liste (`07:30,19:30`). |
| `SCHEDULE_DAYS` | `mon,tue,wed,thu,fri` | Haftanın günleri. |
| `HIGH_LEVEL` | `7` | “Yüksek” sayılan seviye. |
| `WINDOW_MIN_HOURS` | `24` | Önceki rapor yoksa geri dönüş penceresi. |
| `REDACT` | `false` | `PRIVACY_MODE=mask` ile aynı (uyumluluk için). |
| `PRIVACY_MODE` | `off` | `mask`: kişisel veriyi modele gitmeden takma adla değiştirir — bkz. [Gizlilik](Privacy-TR). |
| `PRIVACY_IPS` | `keep` | `public` / `all`: IP adreslerini de takma adla değiştirir. |
| `PRIVACY_DETECT` | `true` | Alarmlarda açık duran kişisel veriyi işaretler. |
| `INVENTORY` | *(boş)* | Beklenen ajan adları; eksik/fazla ajanlar bayrak olur. |
| `RULE_DEPLOY_ENABLED` | `false` | İsteğe bağlı kural dağıtımı (ayrı API kullanıcısı gerekir). |
| `WAZUH_DEPLOY_USER`, `WAZUH_DEPLOY_PASSWORD` | *(boş)* | O ayrı kullanıcı. |
| `RULE_DEPLOY_FILE` | `wdt_rules.xml` | Yöneticide `etc/rules` altındaki tek dosya. |
| `RULE_DEPLOY_ID_MIN`, `RULE_DEPLOY_ID_MAX` | `100000`, `119999` | İzin verilen kural kimlik aralığı. |
| `RULE_DEPLOY_REQUIRE_TESTS` | `false` | Logtest örnekleri eşleşmezse dağıtımı reddet. |
| `RULE_DEPLOY_ALLOW_INCONCLUSIVE` | `false` | Logtest'in yeniden üretemediği örnekleri de dağıt. |
| `MAIL_MAX_PER_HOUR`, `MAIL_ALERT_LEVEL` | *(yok)*, `7` | E-posta kanalı analizi (`ossec.conf` limitleriniz). |

`WDT_ALLOW_INSECURE_TLS=1` ve `WDT_ALLOW_INSECURE_COOKIE=1` üretim açılış kontrolleri için bilinçli laboratuvar
istisnalarıdır; [docs/security-exceptions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md).

## YAML dosyası

`config/environments.example.yaml` eksiksiz ve yorumlu referanstır. İskelet:

```yaml
app:
  timezone: ${TZ:-UTC}
  language: ${APP_LANGUAGE:-en}     # en | tr | es | de
  title: Wazuh Daily Triage

llm:                                 # bloğu atlarsanız LLM_* değişkenleri kullanılır
  provider: anthropic
  model: ${LLM_MODEL}
  api_key: ${LLM_API_KEY}
  max_tokens: 8000
  max_tool_steps: 16

notify:                              # atlarsanız NOTIFY_*/SMTP_*/... kullanılır
  ui_url: ${NOTIFY_UI_URL:-}
  on_run_summary: false

environments:
  - id: prod                         # küçük harf; URL'lerde kullanılır
    name: Production Wazuh
    description: 1 master, 2 worker, 3 indexer
    indexer:
      url: https://wazuh-indexer.example.internal:9200
      username: ${PROD_INDEXER_USER}
      password: ${PROD_INDEXER_PASSWORD}
      ca_file: /app/config/certs/root-ca.pem
      # karşılıklı TLS için client_cert / client_key
    api:                              # isteğe bağlı
      url: https://wazuh-manager.example.internal:55000
      username: ${PROD_API_USER}
      password: ${PROD_API_PASSWORD}
      ca_file: /app/config/certs/root-ca.pem
    alerts_index: wazuh-alerts-4.x-*
    vuln_index: wazuh-states-vulnerabilities-*
    storage_prefix: daily-triage      # sonuçlar daily-triage-runs / -knowledge
    run_retention_days: 0             # >0 eski koşuları siler; bilgi tabanı silinmez
    schedule:
      enabled: true
      times: ["07:30", "19:30"]
      days: [mon, tue, wed, thu, fri]
    window_min_hours: 12
    window_max_hours: 96
    high_level: 7
    max_silence_minutes: 60
    liveness: {enabled: true, interval_minutes: 10}
    privacy: {mode: off, ips: keep, detect: true}   # KVKK / GDPR — bkz. Gizlilik
    context_file: context/prod.md
    seed_file: seed/prod.yaml
    inventory: [web01, db01]          # veya inventory_file
    watch_rules: []
    watch_groups: [authentication_failed, web_scan, sshd]
    rule_deploy:
      enabled: false
      username: ${PROD_DEPLOY_USER:-}
      password: ${PROD_DEPLOY_PASSWORD:-}
      file: wdt_rules.xml
      id_min: 100000
      id_max: 119999
```

Yalnızca YAML'da bulunan ortam seçenekleri (tek ortam modunda `.env` karşılığı yok): `run_retention_days`,
`window_max_hours`, `context_file`, `seed_file`, `vuln_sla`, `promote`, `sources`, `incident`, `anomaly`,
`query`, `mail`, ortam bazlı `llm` ve `notify` geçersiz kılmaları. Her blok için örnek dosyaya bakın.

### Sorgu limitleri (model ve MCP)

```yaml
    query:
      max_range_hours: 336     # tek araç çağrısının en geniş penceresi (14 gün)
      max_buckets: 200         # sorgu başına date_histogram kovası
      max_terms_size: 50       # terms aggregation kova sayısı
      max_size: 25             # dönen belge sayısı
      min_interval: 1m         # en küçük histogram aralığı
      max_concurrent: 8        # ortam başına paralel sorgu
      request_timeout: 30      # saniye; indexer.timeout'a düşer
      extra_fields: [data.custom_field]   # yerleşik alan listesine ekler
```

Model asla ham sorgu göndermez: araçlar sorguyu kurar ve `app/query_guard.py` alan adlarını, pencereyi ve kova
sayılarını önce doğrular. Toplayıcı sabit, gözden geçirilmiş sorgular kullanır ve bu limitlerden etkilenmez;
yani dar bir tavan zamanlanmış koşuyu bozamaz.

## Yeni ortam ekleme

1. `environments:` altına benzersiz, küçük harfli `id` ile blok ekleyin (en çok 41 karakter, `a-z0-9`, `-`, `_`).
2. Kimlik bilgilerini `.env` (veya Kubernetes Secret) içine koyun ve `${DEGISKEN}` olarak referans verin.
3. İsteğe bağlı: `config/context/<id>.md` serbest metin ortam bağlamı ve `config/seed/<id>.yaml` başlangıç
   bilgi tabanı. İkisi de modele verilir.
4. Rolleri sınırlamak gerekiyorsa `ADMIN_ENVS`, `VIEWER_ENVS` ve/veya `MCP_ENVS` ayarlayın.
5. Süreci yeniden başlatın.

```sh
# .env / environments.yaml düzenledikten sonra
docker compose up -d
docker compose exec triage python -m app.check
```

Yapılandırma açılışta okunur; konteyner çalışırken `.env` düzenlemek bir şey değiştirmez. `APP_SECRET`
değişikliği tüm oturumları geçersiz kılar. Parola değişikliği **verilmiş oturumları geçersiz kılmaz** — bunun
için `APP_SECRET` döndürün.

## Yeniden başlatmadan önce doğrulayın

```sh
docker compose exec triage python -m app.check          # indexer, alarmlar, zafiyetler, depolama, API, ek kaynaklar, model (--no-llm atlar)
docker compose exec triage python -c "from app.config import load_settings; s=load_settings(); print([e.id for e in s.environments])"
# bildirimler ayrıca test edilir: ortam sayfası → "Test notification" (POST /api/e/<env>/notify-test)
```

`app/security.py` güvenlikle ilgili ayarları açılışta doğrular. Üretimde örnek parolalar, eksik oturum
anahtarı, güvensiz çerezler, kapatılmış TLS doğrulaması veya eksik kural dağıtımı kimlik bilgileri ya da zayıf
`rule_deploy` parolası nedeniyle açılmayı reddeder (üretim modu: `ENVIRONMENT=production`, eşdeğeri `WDT_ENV`); `AUTH_DISABLED=true`, salt okunur/dağıtım hesabının ortak olması ve `AUDIT_LOG=false`
uyarı üretir.

Sonraki: [Özellikler](Features-TR) · [Gizlilik](Privacy-TR) · [SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR) · [Görüntüleyici modu](Viewer-Mode-TR) ·
[MCP sunucusu](MCP-TR)

---

[English](Configuration) · [Türkçe](Configuration-TR)
