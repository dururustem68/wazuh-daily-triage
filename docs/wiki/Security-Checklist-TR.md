# Üretim öncesi güvenlik kontrol listesi

**Kimin için:** kurulumu onaylayan kişi. Canlıya almadan önce bir kez, erişim biçimi her değiştiğinde (yeni
ingress, SSO, kural dağıtımının açılması) yeniden üzerinden geçin. Her madde nasıl denetleneceğini söyler.

## Sırlar ve hesaplar

- [ ] `APP_PASSWORD` güçlüdür ve başka yerde kullanılmaz; `APP_SECRET` rastgeledir (`openssl rand -hex 32`).
- [ ] Demo ya da örnek değer kalmadı: kurulum `.env.demo` yerine `.env.example` dosyasından başlatıldı ve
      `WDT_DEMO` tanımlı değil.
- [ ] `ENVIRONMENT=production` tanımlı; böylece açılış denetimleri zorunlu olur. Konteyner logunda açılışta
      güvenlik uyarısı yok.
- [ ] Kullanılıyorsa `VIEWER_PASSWORD` yönetici parolasından farklı.
- [ ] Kullanılıyorsa `MCP_TOKEN` ve `METRICS_TOKEN` uzun rastgele değerlerdir ve bir sır deposunda durur.
- [ ] `PRIVACY_SALT` ya da `APP_SECRET` tanımlı; böylece takma adlar yeniden başlatmada değişmez.

## Wazuh erişimi

- [ ] Indexer kullanıcısı özel `daily-triage` hesabıdır: alarm ve zafiyet indekslerinde okuma, yalnız
      `<storage_prefix>-*` üzerinde tam yetki. `admin` değil.
- [ ] Wazuh API kullanıcısı özel, salt okunur `daily-triage` hesabıdır. `wazuh` ya da `wazuh-wui` değil.
- [ ] İkisi de bağlantı testi düğmesiyle ya da `python -m app.check` ile denendi.
- [ ] `storage_prefix`, `wazuh-` ile başlamıyor (**Ayarlar → Depolama güvenliği** bunu gösterir).

## TLS

- [ ] Indexer ve API için `verify_tls` açık, `ca_file` kendi CA'nızı gösteriyor. `WDT_ALLOW_INSECURE_TLS`
      tanımlı değil.
- [ ] Arayüze yalnız HTTPS ile erişiliyor, `COOKIE_SECURE=true` ve konteyner portu genel bir arayüzde
      yayınlanmıyor (Compose `127.0.0.1` üzerinde yayınlar).
- [ ] `FORWARDED_ALLOW_IPS`, proxy'nin konteynerden görünen adresi ya da aralığıdır. Asla `*` değil.

## Kural dağıtımı

- [ ] Gerekmiyorsa: `rule_deploy.enabled` değeri `false` (varsayılan) ve dağıtım kimlik bilgisi yok.
- [ ] Gerekiyorsa: yalnız
      [docs/rule-deployment.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/rule-deployment.md)
      belgesindeki yetkilere sahip **ayrı** bir API kullanıcısı (`daily-triage-deploy`) kullanılıyor, ID aralığı
      (`id_min`–`id_max`) bu iş için ayırdığınız aralık ve `require_tests: true` ayarlı.
- [ ] **Approve and deploy** düğmesine basabilecek kişiler bunun manager'ı yeniden başlattığını biliyor.

## Arayüze erişim

- [ ] `AUTH_DISABLED=true` **yalnız** her isteği doğrulayan bir SSO proxy arkasında kullanılıyor ve uygulamaya
      proxy'yi atlayarak ulaşılamıyor (NetworkPolicy ya da güvenlik duvarı). `TRUSTED_PROXIES` ya da
      `PROXY_SECRET` tanımlı. Bkz. [SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR).
- [ ] SSO ile: `SSO_ADMIN_GROUPS` yalnız karar verip dağıtım yapabilecek az sayıda kişiyi içeriyor, diğer herkes
      görüntüleyici ya da reddediliyor (`SSO_VIEWER_GROUPS`) ve `SSO_DEFAULT_ROLE` değeri `admin` değil. Vekil,
      istemcinin gönderdiği grup başlıklarını siliyor.
- [ ] Tek kurulumda birden çok ortam varsa ve roller her şeyi görmemeliyse `ADMIN_ENVS`, `VIEWER_ENVS` ve
      `MCP_ENVS` ayarlı.

## Ağınızdan çıkan veri

- [ ] Her ortamın hangi model sağlayıcısını hangi koşullarla kullandığını biliyorsunuz. Düzenlemeye tabi
      ortamlar yerel model ya da veri işleme sözleşmesi olan bir sağlayıcı kullanıyor.
- [ ] `privacy.mode` değeri `mask` (0.10.1'den beri varsayılan). Tipik bir log satırını **Ayarlar → Kişisel
      veri maskeleme → Önizleme** alanına yapıştırdınız ve sonuç beklediğiniz gibi.
- [ ] IP adresleri için karar verdiniz: `ips: keep` (varsayılan), `public` ya da `all`.
- [ ] Bildirim alan herkes sunucu adlarını, IP adreslerini ve bulgu başlıklarını görmeye yetkili. Bildirimler
      maskelenmez.
- [ ] MCP: belirteci taşıyan her istemci, maskelenmiş alarm verisini emanet edebileceğiniz bir istemcidir.

## Loglar, denetim izi ve saklama

- [ ] Denetim izi yazılıyor (`AUDIT_LOG` değeri `false` değil), yeniden başlatmada kaybolmayan bir birimde
      duruyor ve merkezi depolamaya gönderiliyor. Kubernetes'te varsayılan `emptyDir` pod ile birlikte gider.
- [ ] Denetim izini, konteyner logunu ve `<storage_prefix>-*` indekslerini kimin okuyabileceği belirlendi.
      Bunlar gerçek sunucu adları, IP'ler ve rapor içeriği taşır.
- [ ] Saklama süreleri belirlendi: raporlar için `run_retention_days`, gönderilen denetim dosyaları için kendi
      politikanız.
- [ ] Hiçbir indeks saklama politikası uygulamanın indekslerini silmiyor (**Ayarlar → Depolama güvenliği**) ve
      ilk yedek alındı. Bkz. [Yedekleme](Backup-TR).

## İşletim

- [ ] İmaj `:latest` yerine bir sürüme ya da digest'e sabitlendi.
- [ ] Tek replika var ya da diğerlerinde `WDT_SCHEDULER=false`.
- [ ] En az bir bildirim kanalı tanımlı ve bildirim testi başarılı; böylece SIEM kesintisi bir kişiye ulaşır.
- [ ] Öneri kutusunun sahibi olarak bir kişi belirlendi.

Her maddenin arka planı: [Güvenlik modeli](Security-Model-TR) ·
[docs/security-exceptions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md)

*0.11.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](Security-Checklist) · [Türkçe](Security-Checklist-TR)
