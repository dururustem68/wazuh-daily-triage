# Gizlilik (KVKK / GDPR)

> **Kısaca:** AI sağlayıcısına herhangi bir şey gönderilmeden önce kişisel veri takma adlarla değiştirilir,
> sırlar ise kalıcı olarak silinir. **0.10.1'den beri varsayılan olarak açık** — `privacy:` bloğu olmayan bir
> kurulum maskeler. Kapatmak için açıkça `privacy.mode: off` yazmak gerekir.

| Kurulumunuzdan çıkan (AI sağlayıcısına / MCP istemcilerine) | Kurulumunuzun içinde kalan |
|---|---|
| takma adlar: `<email:3f9a…>`, `<national_id_tr:…>`, `<iban:…>`, `<phone:…>`, kendi `x_…` türleriniz | gerçek değerler: raporlarda, önerilerde, nöbet sayfasında |
| `<password>`, `<jwt>`, `<private_key>` … — silinir, hiç geri açılmaz | takma ad → değer eşlemesi (yalnızca bellekte, ortam başına) |
| IP adresleri — analiz için **varsayılan olarak açık gider** (`ips: keep`); `ips: public` dış IP'leri, `ips: all` hepsini maskeler | Wazuh'taki veri; hiç değiştirilmez |

Bildirimler (Teams, Telegram, e-posta …) IP, ajan adı ve bulgu başlığı gibi gerçek değerleri taşır: bunun için
güvendiğiniz kanalları seçin.

*0.8.0 ile gelir.* `privacy:` altında ortam bazında ayarlanan iki özellik vardır:

| Özellik | Cevapladığı soru | Varsayılan |
|---|---|---|
| **Maskeleme** (`mode: mask`) | "Kişisel veri LLM'e gidiyor mu?" — gitmez; model yalnızca takma adları görür. | **açık** (0.10.1'den beri) |
| **Tespit** (`detect: true`) | "Loglarımızda olmaması gereken kişisel veri var mı?" — işaretlenir ve öneriye dönüştürülür. | açık |

```yaml
privacy:
  mode: mask            # off | mask
  ips: keep             # keep | public | all
  kinds: []             # boş = tümü; ör. [email, password, national_id_tr, iban, card]
  allow: ['noreply@example\.com']   # asla maskelenmeyen / raporlanmayan değerler (regex)
  detect: true
  detect_sample: 1000   # koşu başına taranan alarm sayısı (0 = kapalı, en fazla 5000)
```

Tek ortam modunda değişkenler: `PRIVACY_MODE=mask`, `PRIVACY_IPS=public` ve `PRIVACY_DETECT=false`. Eski
sürümlerdeki `redact: true` / `REDACT=true` hâlâ çalışır ve `mode: mask` anlamına gelir.

## Maskeleme: modelin gördüğü

```mermaid
flowchart LR
  W[Wazuh / araçlar] -->|gerçek değer| M[Maskeleyici]
  K[bağlam + bilgi tabanı] --> M
  M -->|"email:3f9a1c2b"| L[LLM / MCP istemcisi]
  L -->|"email:3f9a1c2b ile araç çağrısı"| U[geri çevir]
  U -->|gerçek değer| W
  L -->|rapor| U2[geri çevir] --> R[(incelemecinin gördüğü rapor)]
```

| Tür | Örnek | Modele giden | Doğrulama |
|---|---|---|---|
| e-posta | `betul@example.com` | `<email:3f9a1c2b7d4e9a10>` | — |
| telefon | `+90 532 123 45 67`, `0532 123 45 67` | `<phone:…>` | 10–15 hane |
| TCKN | 11 hane | `<national_id_tr:…>` | iki kontrol hanesi |
| Belçika ulusal no | `85.07.30-033.28` | `<national_id_be:…>` | mod 97 |
| Fransa NIR | 15 hane | `<national_id_fr:…>` | anahtar mod 97 |
| IBAN | `TR33 0006 …` | `<iban:…>` | mod 97 |
| kart | `4539 1488 0343 6467` | `<card:…>` | Luhn + kart veren öneki |
| IP (`ips: public/all`) | `203.0.113.7` | `<ip:…>` | `public` iç ağ adreslerini korur |
| parola, token, Bearer, JWT, AWS anahtarı, özel anahtar | `password=…` | `<password>` | silinir — **geri döndürülemez** |

- **Kararlı.** Aynı değer her zaman aynı takma adı alır (`PRIVACY_SALT`, yoksa `APP_SECRET` ile HMAC; 64 bit). Model, aynı hesabın üç ülkeden
  40 başarısız giriş yaptığını yine görür, ama kim olduğunu bilmez.
- **Yalnızca uygulama içinde geri çevrilebilir.** Model bir aracı takma adla çağırdığında, Wazuh sorgulanmadan
  önce gerçek değer yerine konur. Modelin raporu da saklanmadan önce geri çevrilir; incelemeci gerçek değerleri
  görür, model hiçbir zaman görmez.
- **MCP** çıktısı da aynı şekilde maskelenir; Claude Desktop gibi harici bir asistan da sonuçta bir LLM'dir.
- **IP adresleri** GDPR'a göre kişisel veridir, ama analizin çoğu IP'ler üzerinedir; bu yüzden varsayılan `keep`.
  `public` dış IP'leri gizler, iç IP'leri okunur bırakır.
- **Dokunulmayanlar:** run id, zaman damgası, epoch değeri, sürüm ve port. Bir tanımlayıcıya bitişik sayılar
  atlanır ve her sayı türü geçerli bir kontrol hanesi ister.

Sınırlar: bu bir takma adlandırmadır, DLP değildir. Serbest metindeki adlar ("Betül Eser") ve e-posta olmayan
kullanıcı adları tespit edilmez. Düzenlemeye tabi veride (BDDK, KVKK) bunu veri işleme sözleşmesi olan bir
sağlayıcıyla ya da yerel bir modelle birlikte kullanın.

## Maskeleme profili (0.10)

Yukarıdaki algılayıcılar **standart profildir**: yerleşiktir, her kurulumda aynıdır, değiştirilemez.
**Ayarlar → Kişisel veri maskeleme** (yalnızca yönetici) bir kurumun ihtiyacını üstüne ekler:

| | Nedir | Kurallar |
|---|---|---|
| Kendi algılayıcılarınız | bir ad ve desen, örn. `x_musteri_no` = `CUST-\d{6}` → `<x_musteri_no:…>` | adlar `x_` ile başlar; en fazla 20; desenler en fazla 200 karakter, `google-re2` kuruluysa RE2 ile derlenir, değilse bir koşuyu kilitleyemeyecek biçimlerle sınırlıdır (ileri/geri bakış, geri başvuru, iç içe tekrar yok) ve tekrarlı girdiyle süre testinden geçer |
| Hiç maskeleme | okunabilir kalacak değerlerin desenleri (servis hesapları, kendi alan adınız) | YAML'daki `privacy.allow` listesine eklenir |
| Kapatma | sır olmayan bir standart algılayıcı (örn. `phone`) | onay ister, denetim kaydına yazılır; **sır algılayıcıları (parola, belirteç, JWT, anahtarlar) kapatılamaz** |

**Önizleme**, yapıştırılan bir log satırı için modelin ne alacağını kaydedilmemiş formla gösterir; hiçbir şey
gönderilmez ya da saklanmaz. Profil YAML olarak dışa ve içe aktarılabilir. Her değişiklik profil sürümünü artırır
ve her koşu kullandığı sürümü kaydeder (`run.privacy`); böylece bir rapor, geçerli kurallarla ilişkilendirilebilir.

Profil yalnızca ortamda `privacy.mode: mask` ayarlıysa uygulanır; modun kendisi YAML'da kalır.

## Takma ad anahtarı ve kapsamı

Takma adlar, değerin `PRIVACY_SALT` (yoksa `APP_SECRET`) ile HMAC'idir. Yerleşik anahtar yoktur: ikisi de yoksa
her açılışta rastgele bir anahtar üretilir — güvenlidir ama takma adlar yeniden başlatmada değişir (açılışta uyarı
verilir). Belirteçler 64 bittir ve 0.10'dan beri **ortam başınadır**: bir ortamda üretilen `<email:…>` başka bir
ortamda çözülmez.

## Tespit: loglarınızdaki kişisel veri

Her koşu, penceredeki alarmlardan bir örneklemi aynı türler için tarar. Örneklem en yeni `detect_sample` alarm
artı en yoğun 40 log kaynağının her birinden beşer alarmdır. `full_log`, `data.*` ve `rule.description` alanları
taranır; yalnızca sayılar ve tamamen maskelenmiş örnekler saklanır.

- **`personal_data` bayrağı** başlıca kaynakları adlandırır. Örneklemde parola/token, kimlik numarası, IBAN ya da
  kart varsa uyarı, yalnızca e-posta ya da telefon varsa bilgi düzeyindedir.
- **Rapor bölümü** kural × ajan × konum bazında bulunan türleri ve maskelenmiş bir örneği listeler.
  `in_rule_description`, `<description>` içinde `$(alan)` ile değeri kopyalayan bir kuralı işaretler; bu değer o
  kural yüzünden her indekse, her maile ve her panoya düşer.
- **Öneri.** Yapay zekâ gerçek sızıntıları, kaynağında düzeltme önerisiyle bir bulguya dönüştürür ve GDPR Md.
  5(1)(c) ile 32'ye ya da KVKK Md. 12'ye dayanır. Olası düzeltmeler: uygulama logunda maskeleme, log
  göndericide alanı düşürme ya da alanı saklamayan bir decoder/kural; ayrıca zaten indekslenmiş veri için
  saklama süresini kısaltmak. Kimlik doğrulama loglarındaki e-postalar genelde meşrudur; yalnızca URL, sorgu
  dizesi ya da gövde gibi olmaması gereken yerlerde görünürse raporlanır.

Tipik bulgular:

- URL sorgu dizesinde `password=`
- özel bir kuralın açıklamasında müşteri e-postası
- bir uygulamanın debug logunda TCKN

Yanlış pozitifleri `allow` ya da `kinds` ile ayarlayın.

---

[English](Privacy) · [Türkçe](Privacy-TR)
