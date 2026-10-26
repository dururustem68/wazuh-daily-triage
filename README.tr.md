# Wazuh Daily Triage

**[Wazuh](https://wazuh.com) SIEM için yapay zekâ destekli günlük nöbet kontrolü.** Her sabah SIEM'in gerçekten
çalıştığını kontrol eder, gerçek riski bilinen gürültüden ayırır, kısa bir teşhis raporunu Wazuh Indexer'ınıza
geri yazar, yalnızca insan kararı gereken yerde size soru sorar ve cevaplarınızı ertesi gün hatırlar.

Yapay zekâ anahtarınız sizin: Anthropic, OpenAI, Azure OpenAI ya da OpenAI uyumlu herhangi bir uç nokta (Ollama,
vLLM, LM Studio, LiteLLM). Tek Docker konteyner; varsayılan olarak Wazuh'a karşı salt okunur. Kritik durumları ve
koşu özetlerini e-posta, Telegram, Microsoft Teams, Slack, Discord, ntfy ya da jenerik webhook ile bildirir.

[English README](README.md) · [Yapay zekâ sağlayıcıları](docs/providers.tr.md) · [Bildirimler](docs/notifications.md) · [Yetkiler ve ağ](docs/permissions.md) · [Kural uygulama](docs/rule-deployment.md) · [Katkı](CONTRIBUTING.md) · [Güvenlik](SECURITY.md)

![Rapor](docs/screenshot-report-tr.png)

| Öneri kuyruğu | Bilgi tabanı ve kural taslakları |
|---|---|
| ![Öneriler](docs/screenshot-inbox-tr.png) | ![Bilgi tabanı](docs/screenshot-knowledge-tr.png) |

## Ne yapar

- **Zamanlanmış kontrol** (ortam başına günde bir ya da birkaç saat + gün). Pencere "son başarılı koşudan bu yana"; pazartesi
  sabahı hafta sonunu kapsar.
- **Önce deterministik toplama** (yapay zekâdan bağımsız): son alarm zamanı ve boş saatler (kör nokta), indexer
  sağlığı/diski, manager süreçleri, aktif olmayan ajanlar, `ossec.log` hataları, seviye dağılımı, yüksek
  seviye gruplar (kural × ajan × ilk/son × kaynak IP × örnek), önceki pencereyle kıyas, **14 günde ilk kez
  görülen kurallar**, izlenen kurallar, zafiyet özeti.
- **Yapay zekâ teşhisi** — özeti ve bilgi tabanını okur, salt okunur araçlarla derinleşir (zaman dağılımı, IP
  profili, ±30 dk korelasyon, logtest, kural tanımı) ve yapılandırılmış rapor teslim eder. Kural taslağı yazar;
  XML, OS_Regex tuzakları ve ID çakışması için kontrol eder.
- **Yayına alınabilir kural taslakları** — her taslakla manager'da çalıştırılacak hazır komutlar gelir (yedek,
  `wazuh-analysisd -t`, restart, geri alma). İsteğe bağlı **Onayla ve uygula**: taslağı Wazuh API ile ayrı bir
  kural dosyasına yazar, doğrular, yeniden başlatır, yüklendiğini kontrol eder, iki yönlü logtest yapar, hata
  olursa geri alır; alarm susturan/seviye düşüren taslaklar ID yazarak ikinci onay ister
  ([docs/rule-deployment.md](docs/rule-deployment.md)). Varsayılan kapalı.
- **Size sorar** — "Bu SSH girişi sizin miydi?" Cevap bilgi tabanına yazılır, sonraki koşuya bağlam olur.
- **Bilgi tabanı** — bilinen gürültü, kararlar, açık maddeler, dersler, "yarın şuna bak" istekleri. Yapay zekâ
  önerileri **siz onaylayana kadar etkisizdir**. Mevcut notlarınızı YAML ile içe/dışa aktarın (arayüz ya da
  `python -m app.kb`); tekrar çalıştırmak çift kayıt oluşturmaz.
- **Öneri kuyruğu** — bulgular tek tek ve koşular arası tekilleştirilmiş gelir; bir karar tüm tekrarlara uygulanır.
  Sunucuda bakılması gerekenler salt okunur komutlarla gelir; **Sohbette incele** ile çıktıyı yapıştırıp bir sonraki
  adımı alırsınız.
- **E-posta, Telegram, Microsoft Teams, Slack, Discord, ntfy ve jenerik webhook bildirimleri** — kritik durumlar
  (SIEM sessizliği, indexer red, gerçek olay; aynı konu her koşuda tekrarlanmaz), isteğe bağlı her koşu sonrası
  kısa özet ve kural uygulamaları ([docs/notifications.md](docs/notifications.md)).
- **Canlı doğrulama** — uygulanan, onaylanan ya da kalıcı yapılan kural her rapordan sonra gerçek olaylarla
  kontrol edilir: "canlıda 12× doğrulandı (son …)" ya da "5 gündür görülmedi". Logtest'in geçmesi kanıt değildir;
  gerçek olay kanıttır.
- **Kalıcı hale getir** — test edilmiş taslak için *kendi* yapılandırma yönetiminize taşıma paketi: kaynağı
  belirtilmiş kural bloğu, betik (yedek → ekle → çalışan manager'da `wazuh-analysisd -t` → `kubectl apply -k` ya
  da restart → yüklendi mi) ve alarm kataloğunuz için § taslağı.
- **Mail kanalı doluluğu** — `mail:` ayarlıysa her rapor, bir yığının `email_maxperhour` sınırını aştığı saatleri
  ve o saatlerde tetiklenip maili hiç gitmemiş olabilecek diğer kuralları gösterir.
- **Kapsam ve zafiyet SLA'sı** — durum/sürüm/node başına ajanlar, envanter listesinde olup kayıtlı olmayan
  ajanlar ve şiddet başına SLA süresini aşan açık zafiyetler.
- **Aylık denetim raporu** — alarm hacmi, raporlar, bulgular ve kararlarınız, kural değişiklikleri (kim, ne zaman,
  neyi düşürdü), canlılık kontrolünden SIEM kesintileri, kapsam ve zafiyet SLA'sı. Deterministik (yapay zekâ yok),
  PDF ya da Markdown olarak indirilebilir — ISO 27001 / ISMS gözden geçirmeleri için kanıt.
- **Yapay zekâsız anomali** — her rapor kural × ajan sayılarını önceki 14 günle karşılaştırır: sıçramalar
  (z-skoru) ve bir ajanda ilk kez görülen kurallar; yapay zekâ işe buradan başlar.
- **Wazuh'un ötesi (isteğe bağlı)** — salt-okunur Prometheus, Loki ve Kubernetes araçları (pod'lar, yeniden
  başlamalar, OOM, node baskısı, event'ler, pod logları; secret asla): alarmın nedeni tahmin edilmez, kontrol
  edilir ([docs/sources.md](docs/sources.md)).
- **Olay kaydı taslağı** — bulguda tek tık: yapay zekâ kanıtları toplar ve olay şablonunuzu doldurur (zaman
  çizelgesi, kök neden, etki, kanıt sorguları, aksiyonlar); düzenleyin, indirin ya da Zammad veya Jira'da bilet
  olarak açın.
- **MCP sunucusu** — aynı salt-okunur araçlar Claude Desktop ya da herhangi bir MCP istemcisi için: kendi
  asistanınızla canlı veriyle inceleyin ([docs/mcp.md](docs/mcp.md)).
- **Değerlendirme** — `python -m app.eval`, elle incelediğiniz günleri yeniden çalıştırıp yapay zekâyı puanlar
  (yakalama oranı, olay diye raporlanan gürültü, token): modelleri ve promptları sayıyla karşılaştırın
  ([docs/eval.md](docs/eval.md)).
- **Sohbet** — ortam hakkında soru sorun; aynı araçlarla, kanıta dayalı cevap.
- **Kayıtlar Wazuh'un içinde** — her ortamın kendi indexer'ında `daily-triage-runs / -knowledge / -chat`.
- **Çok ortam, çok dil** (İngilizce, Türkçe, İspanyolca, Almanca — sol menünün altından seçilir), ortam başına model (ör. düzenlemeye tabi veri
  için yerel model), arayüzde ve komut satırında bağlantı testi.

## Hızlı başlangıç

### 1. Demo (Wazuh gerekmez)

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git && cd wazuh-daily-triage
cp .env.example .env
sed -i 's/^WDT_DEMO=.*/WDT_DEMO=true/; s/^LLM_PROVIDER=.*/LLM_PROVIDER=mock/; s/^APP_LANGUAGE=.*/APP_LANGUAGE=tr/' .env
docker compose up -d --build
# http://127.0.0.1:8080 — parola: .env'deki APP_PASSWORD
```

### 2. Tek Wazuh ortamı — YAML gerekmez

[docs/permissions.md](docs/permissions.md)'deki salt okunur hesapları açın, sonra `.env`'de `WAZUH_INDEXER_URL`,
`WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`, isteğe bağlı `WAZUH_API_*`, `WAZUH_CA_FILE` ve `LLM_*`
değişkenlerini doldurun:

```sh
docker compose up -d
docker compose exec triage python -m app.check    # ya da ortam sayfasında "Bağlantıları test et"
```

### 3. Birden çok ortam

```sh
cp config/environments.example.yaml config/environments.yaml
vi config/environments.yaml        # her Wazuh için bir blok; parolalar .env'den ${DEGISKEN} ile
vi config/context/<ortam>.md       # ortamı anlatan birkaç satır
```

`config/environments.yaml`, `config/context/*`, `config/seed/*`, `config/certs/` ve `.env` git'e girmez.

### Kubernetes

Bir **[Helm chart](deploy/helm/wazuh-daily-triage)** ve kustomize tabanı, örnek overlay ve isteğe bağlı bileşenler:
**[deploy/kubernetes](deploy/kubernetes/README.md)** — tek replika, root olmayan kullanıcı, salt okunur dosya
sistemi, PVC gerekmez (durum Wazuh Indexer'da). Bileşenler: `networkpolicy`, `ingress-nginx` (TLS, cert-manager,
oauth2-proxy seçeneği) ve `ingress-traefik-authentik` (SSO).

## Yapay zekâ sağlayıcıları

Anahtar sizin. Her sağlayıcı için ayrıntılı kurulum: **[docs/providers.tr.md](docs/providers.tr.md)**.

| Sağlayıcı | `LLM_PROVIDER` | `LLM_BASE_URL` | Örnek `LLM_MODEL` |
|---|---|---|---|
| Claude (Anthropic) | `anthropic` | — | `claude-sonnet-5-5` |
| OpenAI | `openai` | `https://api.openai.com/v1` | `gpt-6.1-sol` ¹ |
| Google Gemini | `openai` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-3.8-flash` |
| DeepSeek | `openai` | `https://api.deepseek.com` | `deepseek-flash` |
| Azure OpenAI | `openai` | `?api-version=` içeren tam deployment adresi | deployment adınız |
| Ollama / vLLM / LM Studio / LiteLLM | `openai` | ör. `http://ollama:11434/v1` | ör. `qwen3:14b` |

¹ OpenAI akıl yürütme modelleri ayrıca `LLM_TOKEN_PARAM=max_completion_tokens` ve `LLM_TEMPERATURE=none` ister.

Model araç kullanımını (function calling) desteklemelidir. Her ortam kendi modelini seçebilir (`llm:` bloğu).

## Bildirimler — e-posta, Telegram, Teams, Slack, Discord, ntfy, webhook

| Ne zaman | Ayar (varsayılan) |
|---|---|
| SIEM sessiz, indexer red, manager süreci durmuş, indexer diski ≥ %90 | `on_critical_flags: true` |
| *Gerçek olay* etiketli ya da *kritik* önemde bulgu | `on_real_incident: true`, `on_critical_findings: true` |
| Koşunun kendisi başarısız | `on_run_error: false` |
| **Her** koşudan sonra kısa özet (sağlık, sayılar, bekleyen öneriler) | `on_run_summary: false` |
| Kural taslağı uygulandı, geri alındı ya da kaldırıldı | `on_rule_deploy: true` |
| **10 dakikada bir canlılık kontrolü** (yapay zekâ yok): indexer/API erişilemez, süreç durdu, SIEM sessiz, disk ≥ %90 — sorun, hatırlatma, düzeldi | `on_liveness: true`, `liveness.interval_minutes` |

Aynı kritik konu `repeat_hours` (24) içinde tekrar gönderilmez. Bir kanal, alanları dolu olduğu anda etkinleşir;
ortam sayfasındaki **Bildirim testi** hepsini dener.

```sh
# .env — kanalları istediğiniz gibi birleştirin
NOTIFY_UI_URL=https://triage.example.internal      # mesajlardaki bağlantı
NOTIFY_ON_RUN_SUMMARY=true

TELEGRAM_BOT_TOKEN=123456789:AA...                 # @BotFather → /newbot
TELEGRAM_CHAT_ID=-1001234567890                    # aşağıya bakın

TEAMS_WEBHOOK_URL=https://...                      # kanal → Workflows → "Post to a channel when a webhook request is received"

SLACK_WEBHOOK_URL=https://hooks.slack.com/...      # Your Apps → Incoming Webhooks
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...   # kanal → Edit → Integrations → Webhooks

WEBHOOK_URL=https://soar.example.internal/hook     # jenerik JSON webhook (Zapier/Make/SOAR)
WEBHOOK_TOKEN=...                                  # isteğe bağlı → Authorization: Bearer

NTFY_TOPIC=wazuh-triage                            # https://ntfy.sh/wazuh-triage (ya da tam URL)
NTFY_TOKEN=...                                     # isteğe bağlı, korumalı konu için

SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_SECURITY=starttls                             # starttls | ssl | none
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=wazuh-triage@example.org
SMTP_TO=secops@example.org,oncall@example.org
```

- **Telegram chat id:** botu gruba ekleyin (ya da bota mesaj yazın), `/start@<botunuz>` gönderin, sonra
  `https://api.telegram.org/bot<token>/getUpdates` adresinde `"chat":{"id":...}` değerini alın; grup id'leri
  eksidir (`-100…`). Wazuh alarmlarını zaten Dashboard'un Notifications eklentisiyle Telegram'a gönderiyorsanız
  aynı bot token'ı ve chat id burada da çalışır.
- **Teams:** eski Office 365 "Incoming Webhook" bağlayıcıları kaldırıldı; yukarıdaki Workflows şablonunu kullanın.
  Mesajlar rapor bağlantılı Adaptive Card olarak gelir.
- **Slack:** bir uygulama oluşturun → *Incoming Webhooks* → kanala ekleyin → Webhook URL'ini kopyalayın. Mesajlar
  rapor bağlantılı block-kit bölümleri olarak gelir.
- **Discord:** kanal → *Edit* → *Integrations* → *Webhooks* → *New Webhook*. Düz metin mesajlar.
- **Jenerik webhook:** JSON gövdesi kabul eden herhangi bir uç nokta (`{"title", "lines", "link", "text"}`);
  `WEBHOOK_TOKEN` ile `Bearer` başlığı ekleyin.
- **ntfy:** `https://ntfy.sh/<topic>` adresine (veya kendi sunucunuza) push; başlık bildirim başlığı olur.
- Çok ortamlı kurulumda aynı anahtarlar `notify:` bloğuna (genel ya da ortam başına) yazılır —
  bkz. [docs/notifications.md](docs/notifications.md).

Mesajlarda ortam adı, bulgu başlıkları, sunucu adları ve IP'ler bulunur; kanalı buna göre seçin.

## Kural taslakları — komutlar ya da tek tıkla uygulama

Bilgi tabanındaki her kural taslağında üç düğme vardır:

- **Komutlar** — manager'da yapıştırılacak blok: yedek, `etc/rules/wdt_rules.xml`'e ekleme, `wazuh-analysisd -t`
  (hata olursa yedeği geri yükler), restart, kontrol, geri alma. Her ortamda çalışır.
- **Onayla ve uygula** — ortam başına isteğe bağlı (`rule_deploy`). Taslağı ayrı, en az yetkili bir API
  kullanıcısıyla yazar, doğrular, manager'ı ya da cluster'ı yeniden başlatır, kural ID'lerinin yüklendiğini
  kontrol eder, iki yönlü logtest yapar ve herhangi bir hatada **kendiliğinden geri alır**. Alarm susturan ya da
  seviye düşüren taslaklar, kural ID'leri yazılarak ikinci kez onaylanır.
- **Wazuh'tan kaldır** — uygulanmış taslağı aynı güvenceyle geri çeker.
- **Canlıda kontrol et / Kalıcı hale getir** — kural uygulandığından beri gerçek olayda tetiklendi mi görün ve
  onu kendi kural dosyanıza / deponuza taşıyacak paketi alın (`promote:` ayarı).

Kurulum ve gereken API yetkileri: [docs/rule-deployment.md](docs/rule-deployment.md).

## Bilgi tabanı içe / dışa aktarma

Elinizdeki notları (bilinen gürültü, kararlar, dersler) YAML listesi olarak getirin — biçim
[`config/seed/example.yaml`](config/seed/example.yaml) ile aynı:

```sh
python -m app.kb import gurultu.yaml -e prod --dry-run   # önizleme
python -m app.kb import gurultu.yaml -e prod --update    # yenileri ekle, değişenleri güncelle (key ya da tür+başlık)
kubectl exec -i deploy/wazuh-daily-triage -- python -m app.kb import - -e prod --update < gurultu.yaml
python -m app.kb export -e prod --kind baseline > baseline.yaml
```

Ya da bilgi tabanı sayfasındaki **İçe / dışa aktar** kutusunu kullanın. Tekrar çalıştırmak çift kayıt oluşturmaz.

## Güvenlik

- Wazuh'a karşı varsayılan olarak **salt okunur**: Active Response, konfig yazma, ajan komutu yok. İsteğe bağlı
  kural uygulama ayrı bir API kullanıcısı kullanır (yalnız özel kural dosyası yükleme + restart); uygulama tek bir
  ayrılmış dosyaya yazar.
- Alarm içerikleri saldırgan kontrolündedir (prompt injection); kandırılmış bir model en fazla bilgi tabanına
  *öneri* ekleyebilir, siz onaylamadan etkisizdir.
- Harici bir LLM kullanıyorsanız alarm özetleri o sağlayıcıya gider. Düzenlemeye tabi ortamlarda (BDDK, KVKK,
  GDPR) yerel model ya da `redact: true` kullanın.
- Arayüz: parola + imzalı çerez, deneme sınırı, sıkı CSP; konteyner root olmayan kullanıcıyla ve salt okunur
  dosya sistemiyle çalışır.

## Lisans

Telif hakkı © 2026 Rüstem Duru. **GNU Affero General Public License v3.0** ile lisanslanmıştır — bkz.
[LICENSE](LICENSE) ve [NOTICE](NOTICE). Değiştirilmiş bir sürümü ağ üzerinden kullanıcılara sunarsanız kaynak
kodunu onlara sunmanız gerekir (`SOURCE_URL`'yi kendi fork'unuza yönlendirin).

Wazuh, Wazuh Inc.'in ticari markasıdır; bu proje Wazuh Inc. ile bağlantılı değildir.
