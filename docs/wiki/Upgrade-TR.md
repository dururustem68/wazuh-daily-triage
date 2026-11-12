# Yükseltme ve geri dönüş

**Kimin için:** operatörler. Aşağıdaki adımlar **önerilen işletim prosedürüdür**. Uygulamanın yerleşik bir
yükseltme ya da sürüm düşürme komutu yoktur: yükseltme, aynı yapılandırma ve aynı veriyle yeni bir imajdır.

## Yükseltme neye dokunur

| | Nerede durur | Yükseltmeyle değişir mi? |
|---|---|---|
| Uygulama | konteyner imajı | evet: yükseltme budur |
| Yapılandırma | `.env`, `config/environments.yaml` ya da Helm değerleri | yalnız sürüm notları bir anahtarın değiştiğini söylüyorsa |
| Raporlar, bilgi tabanı, nöbet olayları, ayarlar | Wazuh Indexer'ınızdaki `<storage_prefix>-*` indeksleri | geçiş adımı yok; yeni sürüm yeni bir indeks ekleyebilir |
| Denetim izi | `audit` birimi ya da log gönderiminiz | hayır |

Durum Indexer'da olduğu için konteyneri değiştirmek hiçbir şey kaybettirmez. Yükseltmedeki risk, değişen bir
varsayılan ya da yeni bir gerekliliktir; bu yüzden önce sürüm notları okunur.

## Yükseltmeden önce

1. Kendi sürümünüzden hedef sürüme kadar
   [CHANGELOG.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/CHANGELOG.md) dosyasını ve
   aşağıdaki sürüm notlarını okuyun.
2. Çalışan sürümü (**Hakkında** sayfası) ve kullanılan imaj etiketini ya da digest'ini not edin.
3. Yedek alın: **Ayarlar → Yedekleme** bölümünden oluşturup indirin ve parolayı bulabileceğiniz bir yerde
   saklayın. Yeni sürüm eskisinin okuyamadığı bir şey yazarsa geri dönüş yolunuz bu yedektir. Bkz.
   [Yedekleme](Backup-TR).
4. Süren bir koşu olmadığından emin olun.

## Yükseltme

Sürümleri sabitleyin. `:latest` ile ne çalıştırdığınızı söyleyemez, ona geri dönemezsiniz.

```sh
# Docker Compose: docker-compose.yml içinde imaj etiketini ayarlayın, sonra
docker compose pull
docker compose up -d
docker compose exec triage python -m app.check
```

```sh
# Helm
helm upgrade wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --namespace wazuh-daily-triage --version <chart sürümü> -f my-values.yaml
```

Kustomize'da overlay'inizdeki uzak base'in `?ref=` değerini ve imaj etiketini değiştirip `kubectl apply -k .`
çalıştırın.

## Yükseltmeden sonra

- Konteyner logu ortamları ve zamanlamayı gösterir, yeni bir güvenlik uyarısı yoktur.
- `python -m app.check` geçer.
- **Ayarlar → Depolama güvenliği** sorunsuzdur.
- Bir koşu başlatın ve raporu açın.
- Eski raporlar ve bilgi tabanı yerinde durur.

## Geri dönüş

Önceki imaj etiketini ya da digest'ini önceki yapılandırmayla kurun:

```sh
# Helm
helm -n wazuh-daily-triage history wazuh-daily-triage
helm -n wazuh-daily-triage rollback wazuh-daily-triage <revizyon>
```

Compose'da önceki etiketi yazıp `docker compose up -d` çalıştırın.

**Geri dönüşün sınırları.** Proje sürüm düşürmeyi test etmez. Yeni sürümün yazdığı belgeler indekslerde kalır
ve eski sürüm bilmediği alanları yok sayabilir. Yalnız yeni sürümde bulunan ayarlar geri dönüşten sonra
etkisizdir. Eski sürüm yeni veriyle düzgün çalışmazsa yükseltmeden önce aldığınız yedeği içe aktarın.

## Sürüm notları

### 0.11.1

- **Uzun işlemler arka planda çalışır.** Kural dağıtma ve kaldırma, bağlantı testi, olay kaydı taslakları ve
  *Ne yapardı?* bir iş ile `202` yanıtı verir; sayfa `GET /api/e/<env>/jobs/<id>` adresini yoklar ve dağıtım
  adımlarını canlı gösterir. Hiçbir vekil zaman aşımı (oauth2-proxy'nin 30 sn'si) bunları artık kesemez. Bu
  rotaları çağırıp sonucu yanıtta bekleyen betikler `?wait=true` ekler.
- **Durum tutan kurallar doğru logtest edilir.** Frekans / `if_matched_*` kuralları logtest adımında her seferinde
  başarısız olup geri alınıyordu (tek olay yalnız üst kurala ulaşır). Örnekler artık tek logtest oturumunda tekrar
  oynatılır.
- **Yarıda kalan dağıtımlar görünür.** Dağıtım ortasında yeniden başlatma, *Uygulanıyor*'da takılı kayıt yerine
  *Yarıda kaldı — yöneticiyi kontrol edin* bırakır.
- **Kubernetes:** `terminationGracePeriodSeconds: 420` (temel manifest ve chart değeri); böylece süren bir dağıtım
  rollout sırasında bitebilir; `JOB_DRAIN_SECONDS` (varsayılan 400) uygulamanın bekleme süresidir.

### 0.11.0

- **SSO rolleri (SSO vekili arkasında işlem gerekir).** 0.11 öncesinde her SSO kullanıcısı yöneticiydi. Artık rol,
  vekilin grup başlığından gelir: `SSO_ADMIN_GROUPS` (isteğe bağlı olarak `SSO_VIEWER_GROUPS`) ayarlayın ve vekilin
  grupları iletmesini sağlayın (`X-authentik-groups`, `X-Auth-Request-Groups`). Bunlar olmadan her SSO kullanıcısı
  salt okunur görüntüleyicidir. Geçiş için `SSO_DEFAULT_ROLE=admin` eski davranışı korur; açılışta uyarı verilir.
  Ayrıntı: [SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR).
- **Yeni arayüz.** Kenar çubuğu menüsü, grafikli pano ve ATT&CK sayfası. Yapılandırma gerekmez; yer imleri
  çalışmaya devam eder. Pano `?env=` ve `?period=24h|7d|30d` parametrelerini alır.
- **Bulgularda ATT&CK etiketleri.** Yeni koşular bulgulara `mitre` ve `mitre_tactics` yazar; eski raporlar etiketsiz
  görünür.
- Pano açıldığında ortam başına iki toplama sorgusu daha (bir dakika önbellekli). Indexer rolüne yeni yetki
  gerekmez.

### 0.10.1

- **Kişisel veri maskeleme varsayılan olarak açık.** `privacy:` bloğu olmayan kurulum artık maskeler. Önceki
  davranışı korumak için açıkça `privacy.mode: off` yazın.
- Docker Compose: denetim izi `audit` adlı birimdedir (önceden `./logs`). Saklamak istiyorsanız mevcut
  `./logs/audit.jsonl` dosyasını birime taşıyın.
- Demonun kendi `.env.demo` dosyası var; `.env.example` artık `WDT_DEMO` ayarlamaz.

### 0.10.0

- İlk açılışta iki yeni indeks oluşturulur: `<önek>-events` ve `<önek>-settings`. `<önek>-*` desenli bir
  Indexer rolü bunları kapsar; `-runs` ve `-knowledge` adlarını tek tek sayan bir rol kapsamaz.
- **Ayarlar**'dan nöbet açılana kadar davranış değişmez.
- SSO modu (`AUTH_DISABLED=true`): kullanıcı başlığı taşımayan istekler `401` alır. Proxy, `USER_HEADER`
  başlıklarından birini iletmelidir.
- Helm: `networkPolicy.enabled` artık `true`; `networkPolicy.ingressNamespace` değerini ayarlayın.
- Eksik depolama indeksi artık sessizce yeniden oluşturulmaz; bkz. [Yedekleme](Backup-TR).
- İlk yedeği alın; hatırlatma yükseltmeden itibaren sayar.

### 0.9.2

- Tarayıcının kökeni uygulamanın gördüğü sunucu adı değilse düğmeler `403` "cross-origin request refused"
  döner: `WDT_TRUSTED_ORIGINS` ayarlayın.
- Üretim modunda, denetim izi yazılamadığı sürece durum değiştiren istekler `503` döner.

Daha eski sürümler: değişiklik günlüğü.

Ayrıca: [Yedekleme](Backup-TR) · [Uyumluluk](Compatibility-TR) · [Sorun giderme](Troubleshooting-TR)

*0.11.1 için geçerlidir · gözden geçirme: 2026-11-12*

---

[English](Upgrade) · [Türkçe](Upgrade-TR)
