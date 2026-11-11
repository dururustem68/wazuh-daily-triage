# Sorun giderme

**Kimin için:** operatörler. Gördüğünüz iletiyi bu sayfada arayın. Her satır denetimi, olası nedeni ve çözümü
verir. Komutlar Docker Compose içindir; Kubernetes'te `docker compose exec triage` yerine
`kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage --`, `docker compose logs triage` yerine
`kubectl -n wazuh-daily-triage logs deploy/wazuh-daily-triage` kullanın.

## İlk üç denetim

```sh
docker compose ps                                  # çalışıyor ve sağlıklı mı?
docker compose logs --tail 100 triage              # açılış satırları neyin yanlış olduğunu söyler
docker compose exec triage python -m app.check     # Indexer, API, kaynaklar, model
```

`python -m app.check <ortam>` tek ortamı test eder, `--no-llm` modeli atlar. Ortamın **Raporlar** sayfasındaki **Bağlantıları
test et** düğmesi aynı testi çalıştırır. Her log satırı ve her denetim kaydı bir istek kimliği taşır
(`X-Request-ID` yanıt başlığı); logda bu kimliği aramak isteğin tamamını verir.

## Konteyner açılmıyor

| İleti ya da belirti | Neden | Çözüm |
|---|---|---|
| `refusing to start in production` | bir üretim güvenlik denetimi başarısız; ileti değişkenin adını verir | gerçek bir `APP_PASSWORD`, `APP_SECRET`, `COOKIE_SECURE=true` ayarlayın ya da TLS doğrulamasını düzeltin |
| `no configuration: … does not exist and WAZUH_INDEXER_URL is not set` | ne YAML dosyası ne de tek ortam değişkenleri var | demo: `cp .env.demo .env`. Gerçek: `WAZUH_INDEXER_URL` ayarlayın ya da `config/environments.yaml` oluşturun |
| `.env` içinde `WDT_DEMO=true` olduğu hâlde demo kapanıyor | değişken iki kez geçiyor; son satır geçerli | `.env.demo` dosyasını değiştirmeden kullanın |
| 127.0.0.1:8080 adresinde `ERR_EMPTY_RESPONSE` | konteyner yeniden başlıyor | `docker compose logs triage` çıktısını okuyun |
| Bir değer `#` ve ardındaki metni içeriyor | `.env` içinde değer satırına yorum yazılmış | yorumları ayrı satıra alın |
| `ZoneInfoNotFoundError` | `TZ` bir IANA adı değil | örneğin `TZ=Europe/Istanbul` |

## Giriş ve web arayüzü

| İleti ya da belirti | Neden | Çözüm |
|---|---|---|
| Giriş tekrar giriş sayfasına dönüyor | düz HTTP üzerinde `COOKIE_SECURE=true` ya da proxy çerezleri düşürüyor | HTTPS kullanın; `COOKIE_SECURE=false` yalnız yerel test için |
| Herkes için "çok fazla deneme" uyarısı | iletilen başlıklar yok sayıldığı için bütün kullanıcılar tek adres görünüyor | `FORWARDED_ALLOW_IPS` değerini proxy'nin konteynerden görünen adresi yapın |
| `401` "did not come through the authenticating proxy" | SSO modunda kullanıcı başlığı yok | `X-Forwarded-User` ya da `X-authentik-username` iletin; `TRUSTED_PROXIES` ve `PROXY_SECRET` değerlerini denetleyin |
| Bir düğmede `403` "cross-origin request refused" | tarayıcının `Origin` değeri uygulamanın gördüğü sunucu adı değil | `WDT_TRUSTED_ORIGINS=https://genel.adresiniz` |
| İşlemde `403`, sayfa salt okunur diyor | görüntüleyici parolasıyla girilmiş ya da (SSO) `SSO_ADMIN_GROUPS` içindeki bir grupta değil | yönetici olarak girin; vekilin ilettiği grup adını denetleyin |
| `403` "rolü yok" | SSO: kullanıcı listelenen hiçbir grupta değil ve `SSO_DEFAULT_ROLE` değeri `deny` | kullanıcıyı `SSO_ADMIN_GROUPS` / `SSO_VIEWER_GROUPS` içindeki bir gruba ekleyin |
| SSO: 0.11'e yükseltmeden sonra herkes salt okunur | `SSO_ADMIN_GROUPS` yok ya da vekil grup başlığı iletmiyor | grupları tanımlayın; `X-authentik-groups` / `X-Auth-Request-Groups` iletin ([SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR)) |
| *Bu ortama erişim yetkiniz yok* | rolün ortam listesi bu ortamı içermiyor | `ADMIN_ENVS` / `VIEWER_ENVS` |
| `503` "audit trail is not writable" | üretim modu denetim izi olmadan değişikliği reddeder | log dizinini yazılabilir yapın (`audit` birimi) |
| Proxy'den `502`, konteyner sağlıklı | proxy yanlış sunucuya ya da porta bakıyor | port 8080; `docker compose ps` |
| "Bazı kayıtlı veriler yüklenemedi" uyarısı | Indexer'dan bir okuma başarısız | Indexer'ı denetleyin; uyarı istek kimliğini gösterir |

## Indexer: bağlantı, TLS, kimlik doğrulama

Önce uygulamanın dışında, aynı hesap ve CA ile deneyin:

```sh
curl -sS --cacert config/certs/root-ca.pem -u 'daily-triage:PAROLA' \
  "https://<indexer>:9200/wazuh-alerts-*/_count"
```

| Sonuç | Neden | Çözüm |
|---|---|---|
| sertifika doğrulanamadı | yanlış ya da eksik CA; ya da sertifika kullandığınız sunucu adını içermiyor | CA'yı `config/certs/` altına koyun ve `ca_file` değerini **konteyner içindeki** yola ayarlayın (`/app/config/certs/…`); sertifikada geçen adı kullanın |
| `401` | yanlış parola ya da kullanıcı silinmiş | wazuh-docker ve wazuh-kubernetes'te `securityadmin`, REST API ile oluşturulan kullanıcıları silebilir; kullanıcıyı YAML dosyalarında tanımlayın |
| `wazuh-alerts-*` için `403` | okuma yetkisi ya da rol eşlemesi eksik | yetki belgesindeki rolü ve eşlemeyi yeniden uygulayın |
| 0.10'a yükseltmeden sonra `daily-triage-events` ya da `-settings` için `403` | rol eski indeks adlarını tek tek sayıyor | role `<önek>-*` verin |
| Zaman aşımı | yönlendirme, güvenlik duvarı ya da NetworkPolicy | konteynerin ağından deneyin |
| Depolama güvenliği *denetlenemedi* gösteriyor | kullanıcı ISM politikalarını okuyamıyor | isteğe bağlı: ISM okuma yetkisi verin; yoksa politikaları kendiniz denetleyin |

Üretimde sertifika hatasını aşmak için `verify_tls: false` yapmayın; uygulama bununla açılmaz.

## Wazuh API: bağlantı ve yetkiler

| Belirti | Neden | Çözüm |
|---|---|---|
| Raporun ajan, daemon ve kural bölümleri boş | API tanımlı değil, erişilemiyor ya da yetkisi yok | `api:` / `WAZUH_API_*` ayarlayın; yetki belgesindeki salt okunur kullanıcıyı oluşturun |
| Kullanıcı oluşturulamıyor | Wazuh parola kuralı: 8–64 karakter; büyük harf, küçük harf, rakam ve simge | kurala uyan bir parola seçin |
| Politika oluştururken `4009` | aynı politika başka bir adla zaten var | o politikanın ID'sini kullanın |
| Logtest yok | rolde `logtest:run` eksik | ekleyin |
| Cluster'da durum yanlış görünüyor | `api.url` bir worker'ı gösteriyor | master'ı gösterin |

API olmadan alarm analizi yine çalışır.

## Rapor boş, gecikmiş ya da eksik

| Belirti | Neden | Çözüm |
|---|---|---|
| Zamanında rapor yok | konteyner çalışmıyordu, zamanlama kapalı, saat dilimi yanlış | çalışır tutun; `schedule.enabled`; `TZ` |
| Düğme "meşgul" diyor (`409`) | bu ortam için bir koşu sürüyor | bekleyin; yarıda kalmış koşu bir sonraki açılışta toparlanır |
| Pencere beklenenden kısa ya da uzun | son **başarılı** koşudan başlar; `window_max_hours` sınırlar | tek seferlik için ortamın **Raporlar** sayfasında sabit pencere seçin |
| "Toplama hataları (kör nokta)" satırları var | tekil sorgular başarısız | gösterilen nedeni giderin; raporun o bölümü temiz değil, boştur |
| Wazuh'ta alarm var ama sayı sıfır | yanlış `alerts_index` ya da hesap okuyamıyor | deseni ve yukarıdaki `_count` testini denetleyin |
| Yalnız bayraklar var, bulgu yok; özet yapay zekâ hatasından söz ediyor | modele ulaşılamadı ya da model rapor teslim etmedi; yerine deterministik rapor kaydedildi | sonraki bölüme bakın; sorular bir sonraki koşuya açık kalır |
| Durumu *hata* olan koşu | beklenmeyen bir hata; koşu aşamayı ve iletiyi gösterir | sonraki koşu son başarılı pencereden başlar; istek kimliğiyle bildirin |

## Model sorunları

| Belirti | Neden | Çözüm |
|---|---|---|
| Araç çağrısı sayısı 0 ve zayıf rapor | model araç (fonksiyon) çağırmayı desteklemiyor ya da yok sayıyor | araç çağırabilen bir model seçin; küçük yerel modeller araçları sık atlar |
| *Model rapor teslim etmedi* | model rapor aracını çağırmadan durdu ya da adım sınırına takıldı | `max_tool_steps` değerini yükseltin; daha güçlü bir model deneyin |
| "output limit reached" notu | cevap belirteç sınırında kesildi | `max_tokens` değerini yükseltin |
| OpenAI akıl yürütme modelinden `400` | parametre adları farklı | `LLM_TOKEN_PARAM=max_completion_tokens`, `LLM_TEMPERATURE=none` |
| Sağlayıcıdan `401` / `404` | yanlış anahtar, temel adres ya da model kimliği | `LLM_*` değerlerini [docs/providers.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/providers.md) ile karşılaştırın |
| Maliyet beklenenden yüksek | koşu başına çok araç adımı ya da çok koşu | `max_tool_steps` değerini düşürün; günde bir ya da iki AI turu; nöbet ve canlılık kontrolü modeli hiç çağırmaz |

Modelleri izlenimle değil sayıyla karşılaştırın: `python -m app.eval`
([docs/eval.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/eval.md)).

## Bildirimler

| Belirti | Neden | Çözüm |
|---|---|---|
| Hiçbir şey gelmiyor | hiçbir kanalın alanları tam değil | ortamın **Raporlar** sayfasında **Bildirim testi** düğmesine basın; kanal kanal sonuç verir |
| Koşu özeti gelmiyor | varsayılan olarak kapalı | `notify.on_run_summary: true` |
| Aynı kritik madde tekrarlanmıyor | tasarım gereği, `repeat_hours` (24) içinde | – |
| Teams: gelmiyor | eski Office 365 bağlayıcıları kaldırıldı | Workflows webhook'unu kullanın |
| Telegram: gelmiyor | yanlış sohbet kimliği (grup kimlikleri negatiftir) ya da bot grupta değil | kimliği `getUpdates` çıktısından alın |
| E-posta reddediliyor | kullanıcı adıyla `security: none` kullanılamaz | `starttls` ya da `ssl` kullanın |
| Nöbet hiçbir şey duyurmuyor | nöbet kapalı, kanal işaretli değil, sessiz saatler ya da olay susturulmuş / bilinen gürültü | **Nöbet** sayfası her olayın durumunu gösterir |

## Kural dağıtımı

| Belirti | Neden | Çözüm |
|---|---|---|
| Düğme pasif | `rule_deploy` açık değil | [Kural yaşam döngüsü](Rule-Lifecycle-TR) |
| Kural dağıtımı açıkken uygulama açılmıyor | dağıtım kullanıcısının adı ya da parolası boş, ya da parola örnek bir değer | ayrı dağıtım kullanıcısı için gerçek kimlik bilgisi girin |
| Açılışta dağıtım kullanıcısı uyarısı | salt okunur kullanıcıyla aynı hesap | ayrı kullanıcı oluşturun |
| `Permission denied: Resource type: rule:file` | `rules:delete` politikası `rule_deploy.file` değerinden farklı bir dosyayı gösteriyor | adları eşitleyin |
| `Permission denied: Resource type: *:*` | `rules:update` bir dosyaya daraltılmış; Wazuh yalnız `*:*:*` kabul eder | politikayı düzeltin |
| Geri alındı, *inconclusive* | bir örnek hiçbir kuralla eşleşmedi | örneği üst kurala ulaşacak biçimde düzeltin; `allow_inconclusive` yalnız belgelenmiş istisna olarak |
| Üst kural bilinmiyor | `etc/rules` içindeki dosyaların yükleme sırası | hem ayarda hem politikada daha sonra sıralanan bir ad kullanın, örneğin `zz_wdt_rules.xml` |
| Geri alma **başarısız** (logda kritik) | manager geri yüklenen dosyayı kabul etmedi ya da yeniden başlamadı | bir kişi manager'a bakmalı: manager'da `wazuh-analysisd -t`, sonra dosya |
| Yeniden başlatma zaman aşımına uğruyor | yavaş cluster | `restart_timeout` değerini yükseltin |

## Kubernetes

| Belirti | Neden | Çözüm |
|---|---|---|
| Pod döngüde yeniden başlıyor | bir açılış denetimi başarısız | `kubectl logs --previous` iletiyi gösterir |
| Hazır, ama bağlantı kontrolleri zaman aşımına uğruyor | NetworkPolicy giden kuralları | Indexer, API ve ek kaynaklara izin verin; bkz. [Kubernetes](Kubernetes-TR) |
| Ingress `502`/`503` veriyor | politikadaki `ingressNamespace` sizin controller'ınızın ad alanı değil | `networkPolicy.ingressNamespace` ayarlayın |
| SSO modunda 0.10'a yükseltmeden sonra her sayfa `401` | proxy kullanıcı başlığı iletmiyor | `USER_HEADER` başlıklarından birini iletin |
| Her kontrol iki kez çalışıyor | birden fazla replika | tek replika ya da diğerlerinde `WDT_SCHEDULER=false` |
| Yeniden başlatmadan sonra denetim izi boş | `emptyDir` | gönderin ya da birim bağlayın |

Readiness ve liveness hiçbir zaman Wazuh'a bağlı değildir. Wazuh kapalıyken pod'un hazır olması istenen
davranıştır.

## MCP

| Belirti | Neden | Çözüm |
|---|---|---|
| `/mcp` için `404` | `MCP_TOKEN` tanımlı değil; uç nokta kapalı | tanımlayıp yeniden başlatın |
| `401` | yanlış belirteç; tekrarlanan hatalar adresi bir süre kilitler | belirteç dosyasını denetleyin; bekleyin |
| `429` "rate limit exceeded" | tek adresten dakikada 120'den fazla istek | bir dakika bekleyin ya da `MCP_RATE_PER_MINUTE` |
| `GET /mcp` için `405` | olağan: sunucudan başlatılan akış yoktur | – |
| İstemci SSO giriş sayfasını gösteriyor | `/mcp` SSO proxy üzerinden yönlendiriliyor | `/mcp` yolunu girişin dışından yönlendirin; kendi belirteci vardır |
| Bir ortam eksik | `MCP_ENVS` | ekleyin |
| İstemciden sunucu adı çözülmüyor | arayüze yalnız iç ağınızdan ya da VPN'den erişiliyor | VPN'e bağlanın ya da stdio köprüsünü erişebilen bir makinede çalıştırın |

## Depolama ve yedekleme

| Belirti | Neden | Çözüm |
|---|---|---|
| Kırmızı uyarı: indeks eksikti | bir saklama politikası ya da bir kişi uygulama verisini silmiş | **Ayarlar → Yedekleme** bölümünden içe aktarın ya da kaybı onaylayın. Bkz. [Yedekleme](Backup-TR) |
| Arşiv açılmıyor | yanlış parola ya da dosya değişmiş | parola olmadan kurtarma yoktur |
| Otomatik yedek alınmıyor | S3, `BACKUP_PASSPHRASE` ve Ayarlar'daki anahtar gerekir | üçünü de yapılandırın |

## Sorun bildirirken

Sürümü (Hakkında sayfası), kurulum biçimini, istek kimliğini ve ilgili log satırlarını içeren bir kayıt açın.
Önce sunucu adlarını, IP adreslerini ve belirteçleri çıkarın. Güvenlik sorunları
[GitHub güvenlik bildirimleri](https://github.com/dururustem68/wazuh-daily-triage/security/advisories/new)
üzerinden özel olarak iletilir.

*0.11.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](Troubleshooting) · [Türkçe](Troubleshooting-TR)
