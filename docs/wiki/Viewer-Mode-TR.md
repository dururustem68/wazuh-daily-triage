# Görüntüleyici modu (salt okunur rol)

Salt okunur rol, meslektaşların hiçbir şeyi değiştirmeden her şeyi okumasını sağlar. İki yolla verilir: ikinci bir
uygulama parolası (`VIEWER_PASSWORD`, bu sayfa) ya da SSO vekili arkasında `SSO_VIEWER_GROUPS` içinde listelenen
bir grubun üyeliği ([SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR), 0.11'den beri). İkisi de aynı rolü ve aynı
yetki matrisini verir.

Raporları ve açık
önerileri görmesi gereken yöneticiler, denetçiler, SOC vardiya liderleri ve uygulama sahipleri için
tasarlanmıştır; triage çalıştırma veya kural dağıtma yetkisi vermez.

![Salt okunur görüntüleyici](images/viewer-mode.png)

## Etkinleştirme

```sh
# .env
VIEWER_PASSWORD=<güçlü bir parola, APP_PASSWORD'dan farklı>
AUTH_DISABLED=false          # görüntüleyici modu uygulama parolası özelliğidir
```

Konteyneri yeniden başlatın. Giriş sayfası artık salt okunur görüntüleyici girişinin mevcut olduğunu söyler.
İki parola aynı formu kullanır; rolü, eşleşen parola belirler:

| Parola | Rol | Oturum |
|---|---|---|
| `APP_PASSWORD` | `admin` | imzalı çerez, 12 saat |
| `VIEWER_PASSWORD` | `viewer` | imzalı çerez, 12 saat |

Üretimde, `APP_PASSWORD` ile aynı olan `VIEWER_PASSWORD` için uygulama **açılmaz**. Boş değer rolü kapatır.

## Görüntüleyici ne yapabilir?

| İzin | Admin | Görüntüleyici | Kapsam |
|---|---|---|---|
| `read` | ✓ | ✓ | pano, raporlar, öneri gelen kutusu, bilgi tabanı ve YAML dışa aktarımı, denetim raporu, terfi paketi görüntüleme, **Nöbet** sayfası (olaylar ve AI hükümleri), kopyalar ve PDF'ler |
| `run` | ✓ | – | triage koşusu, canlılık kontrolü, bağlantı testi, bildirim testi, Nöbet sayfasında **Şimdi tara** |
| `decide` | ✓ | – | bulgu kararları, soruları yanıtlama, gelen kutusu işlemleri, olay kayıtları |
| `knowledge` | ✓ | – | bilgi kaydı oluşturma/güncelleme/silme, içe aktarma |
| `deploy` | ✓ | – | kural taslağı onaylama/dağıtma/geri alma/kalıcılaştırma |
| `admin` | ✓ | – | ortam düzeyi işlemler, `METRICS_TOKEN` olmadan `/metrics` ve **Ayarlar** altındaki her şey — okumak dahil: nöbet, AI turu, maskeleme profili (ve YAML dışa aktarımı), yedek dışa/içe aktarma, depolama kaybını onaylama |

Hiçbir izne eşlenmemiş bir yazma rotası `admin` ister (0.9.2'den beri kapalı varsayılan); bir test tüm rotaları
denetler, böylece yeni bir özellik kendini yanlışlıkla görüntüleyiciye açamaz.

Matris `app/authz.py` içindedir; HTTP middleware **her** rotada kontrol eder. Düğmeyi gizlemek kontrol değildir:
elle hazırlanmış bir `POST` `403` alır ve denetim kaydına `denied:<izin>` olarak yazılır.

### Bilinen kozmetik sınır

Kenar çubuğu görüntüleyiciden **Ayarlar**'ı gizler ve pano **Şimdi kontrol et** düğmesini pasif gösterir; ancak bazı
yazma kontrolleri (örneğin rapordaki ve öneri kutusundaki karar düğmeleri) hâlâ gösterilir. Kapalı davranırlar — sunucu isteği reddeder — ama görünürler. Sınır olarak düğmenin yokluğunu değil, 403'ü
kabul edin.

## Görüntüleyicinin gördüğü ortamları sınırlama

Üretim, hazırlık ve müşteri ortamları tek kurulumu paylaşıyorsa rolleri kapsamlandırın:

```sh
VIEWER_ENVS=staging,lab        # boş = tüm ortamlar
ADMIN_ENVS=prod,staging,lab    # isteğe bağlı, boş = tümü
```

Liste dışındaki bir ortamın URL'sini açan görüntüleyici `403` sayfası görür ve ret denetlenir. Aynı kontrol
sayfa işleyicilerinin içinde de çalışır; tahmin edilen bir ortam kimliği veri sızdırmaz.

## Doğrulama

1. Çıkış yapın, `VIEWER_PASSWORD` ile giriş yapın.
2. Kenar çubuğunda **read-only** etiketi görünür; pano raporları ve önerileri gösterir.
3. Bir bulguyu açın: karar düğmeleri ve **Incident record draft** işe yaramaz — istek `403` ile reddedilir.
4. **Run check now** deneyin: koşu başlamaz ve listede yeni koşu görünmez.
5. Denetim kaydını kontrol edin:

```sh
tail -n 5 logs/audit.jsonl
# {"action":"denied","actor":"ui","role":"viewer","result":"denied:run",...}
```

6. Görüntüleyici oturumuyla `GET /metrics` `403` döner; `METRICS_TOKEN` tanımlıysa kimlik bilgisi oturum
   değil, bearer token olur.

## Operasyonel notlar

- **Oturumlar 12 saat sürer.** `POST /logout` çerezi siler.
- **Parolayı değiştirmek mevcut oturumları bitirmez.** Çerezde rol ve son kullanma tarihi var, parola yok.
  Hepsini hemen geçersiz kılmak için `APP_SECRET` değiştirin.
- **Parola tüm görüntüleyiciler tarafından paylaşılır.** Bireysel görüntüleyici hesabı ve kişi bazlı denetim
  kimliği yoktur: denetim kaydı rolü `viewer`, aktörü ortak `ui` olarak yazar (yalnızca giriş kayıtlarında
  aktör `viewer`). Adlandırılmış salt okunur kullanıcılar gerekiyorsa SSO ile `SSO_VIEWER_GROUPS` kullanın
  (aşağıda).
- **GET isteklerinden CSRF riski yoktur.** Tüm durum değiştiren işlemler `POST`/`DELETE`'tir ve aynı izin
  kontrolünden geçer.

## Görüntüleyici modu ve SSO (0.11)

SSO vekili arkasında (`AUTH_DISABLED=true`) parola girişi kapalıdır; bu yüzden `VIEWER_PASSWORD` kullanılmaz. Rol
bunun yerine kullanıcının gruplarından gelir:

```sh
AUTH_DISABLED=true
SSO_ADMIN_GROUPS=wazuh-admins       # yöneticiler
SSO_VIEWER_GROUPS=soc,auditors      # salt okunur görüntüleyiciler; diğer herkes reddedilir
```

| | Görüntüleyici parolası | SSO görüntüleyici grubu |
|---|---|---|
| Kim | ortak parolayı bilen herkes | her kişi, kendi hesabıyla |
| Denetim kaydındaki aktör | `ui` (ortak) | vekilden gelen kullanıcı adı |
| Erişimi geri almak | parolayı ve `APP_SECRET`'i değiştirmek | kullanıcıyı gruptan çıkarmak |
| Yetkiler | yukarıdaki matris | aynı matris |
| Ortamlar | `VIEWER_ENVS` | `VIEWER_ENVS` |

Grup başlığı adları, vekil yapılandırması ve hiçbir listede olmayan kullanıcıların varsayılan rolü:
[SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR).

## Güvenlik kontrol listesi

- `VIEWER_PASSWORD` uzun, benzersiz ve `APP_PASSWORD`'dan farklı.
- `APP_SECRET` ayarlı; oturumlar yeniden başlatmada korunur ve taklit edilemez.
- TLS arkasında `COOKIE_SECURE=true`.
- Açılış kontrolleri için `ENVIRONMENT=production`.
- Kurulum paylaşımlıysa hazırlık/müşteri verisini `VIEWER_ENVS` ile sınırlayın.
- Denetim sevkiyatı yapılandırılmış (`logs/audit.jsonl` 20 MB'ta döner, üç nesil tutar). Dosya hash zinciriyle
  bağlıdır: her satırda `prev` ve `hash` bulunur, böylece değiştirilen veya silinen satır tespit edilir.

  ```sh
  docker compose exec triage python -c "from app import auditlog; print(auditlog.verify())"
  # {'ok': True, 'lines': 42, 'broken': None, 'file': 'logs/audit.jsonl'}
  ```

Wazuh'un en az yetkili hesapları ve denetim biçimi için [docs/permissions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md).

---

[English](Viewer-Mode) · [Türkçe](Viewer-Mode-TR)
