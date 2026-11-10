# Yedekleme, geri yükleme ve indeks silme kuralları

*0.10.0'dan beri.* Uygulamanın bildiği her şey — bilgi tabanı, kararlar, raporlar, nöbet olayları, ayarlar —
**sizin** Wazuh indexer'ınızdaki `<storage_prefix>-*` indekslerinde durur. Başka bir veritabanı yoktur. Bu
kurulumu basit tutar; ama bir indeks silme kuralı uygulamanın hafızasını hiçbir hata vermeden silebilir.

## Verim cluster'ın silme kurallarından güvende mi?

**Ayarlar → Depolama güvenliği** bunu her kurulumda, salt okunur olarak denetler:

1. **Önek.** `wazuh-` ile başlayan bir `storage_prefix`, Wazuh'un kendi indeks desenlerine (`wazuh-*`) girer;
   Wazuh indeksleri için yazılmış silme kuralları uygulamanın verisine de uygulanır. Varsayılan `daily-triage`
   güvenlidir. Açılışta da uyarı loglanır.
2. **Politika.** Her indeks için: bir Index State Management politikası bağlı mı, içinde `delete` adımı var mı,
   silme hangi tarihte olur. `*` desenli bir politika bu indeksleri de yakalar. Indexer kullanıcısının ISM okuma
   yetkisi yoksa (`cluster:admin/opendistro/ism/*`) sonuç *denetlenemedi* olur — asla "politika yok" değil.
3. **Kayıp.** Eksik bir indeks sessizce yeniden oluşturulmaz. Uygulama onu oluşturur (çalışmak için gerekir),
   kaybı kaydeder, `storage_lost` kritik bayrağını kaldırır, her sayfada uyarı gösterir ve bildirim gönderir.
   Uyarı, bir yönetici yedeği geri yükleyene ya da kaybı onaylayana kadar kalır. Yepyeni bir kurulumda tek bir
   bildirim indekslerin oluşturulduğunu söyler.
4. **Hatırlatma.** Son dışa aktarım `remind_days` değerinden (varsayılan 30; hiç olmadıysa kurulumdan itibaren)
   eskiyse her koşu bilgi bayrağı taşır ve haftada en fazla bir bildirim gönderilir.

Bu indeksleri her şeyi yakalayan bir politikanın dışında tutmak için o politikanın `ism_template.index_patterns`
desenini daraltın (örneğin `wazuh-alerts-*`, `wazuh-archives-*`) ya da politikayı uygulamanın indekslerinden kaldırın:

```
POST _plugins/_ism/remove/daily-triage-*
```

## Dışa aktarma

**Ayarlar → Yedekleme → Oluştur ve indir.** Bir parola seçersiniz (en az 12 karakter); arşiv
(`wdt-<ortam>-<zaman>.wdtbak`) sıkıştırılır ve scrypt + AES-256-GCM ile şifrelenir. Parola olmadan açılamaz;
bozulmuş ya da değiştirilmiş dosya reddedilir. Arşivde kimlik bilgisi yoktur. Rota `admin` izni ister ve her
dışa aktarım denetim kaydına yazılır.

### S3

Yapılandırmada (asla arayüzde değil) bir kova tanımlayın; dışa aktarma formu "S3'e de gönder" seçeneğini sunar:

| Değişken | Anlamı |
|---|---|
| `BACKUP_S3_ENDPOINT` | `https://s3.eu-central-1.amazonaws.com`, MinIO/Ceph/Hetzner uç noktası … |
| `BACKUP_S3_BUCKET`, `BACKUP_S3_REGION` | kova ve bölge (sağlayıcıda bölge yoksa `us-east-1`) |
| `BACKUP_S3_ACCESS_KEY`, `BACKUP_S3_SECRET_KEY` | o kovaya yalnızca `PutObject` yapabilen bir anahtar |
| `BACKUP_S3_PREFIX` | anahtar öneki, varsayılan `wazuh-daily-triage` |
| `BACKUP_S3_PATH_STYLE` | `https://host/kova/anahtar` için `true` (varsayılan), `https://kova.host/anahtar` için `false` |
| `BACKUP_PASSPHRASE` | yalnızca **otomatik** yedek için gerekir |

Otomatik yedek; S3 **ve** `BACKUP_PASSPHRASE` tanımlıysa **ve** Ayarlar → Yedekleme'deki anahtar açıksa çalışır
(varsayılan 7 günde bir). S3 olmadan otomatik yedek yoktur: koruduğu verinin yanında duran bir arşiv yedek değildir.

## İçe aktarma

Arşivi yükleyin, parolayı girin, **önizleyin**. Önizleme her tür için neyin ekleneceğini, değişeceğini ya da
olduğu gibi kalacağını listeler. Sonra:

- **eksikleri ekle** — var olan kayıtlara asla dokunulmaz;
- **üzerine yaz** — aynı kimlikli kayıtlar değiştirilir ve arşivdeki ayarlar uygulanır.

İçe aktarılan kural taslakları onaylı/uygulanmış durumunu kaybeder ve yeniden onaylanmalıdır; arşiv bir kuralı
manager'a koymanın yolu asla olamaz. Başka bir ortamın arşivi de içe aktarılabilir (önizleme bunu söyler).

Ayrıca: [Nöbet](Watch-TR) · [Yapılandırma](Configuration-TR) · [Kurulum](Installation-TR)

---

[English](Backup) · [Türkçe](Backup-TR)
