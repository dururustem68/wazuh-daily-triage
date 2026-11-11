# Başlangıç: demodan ilk gerçek rapora

**Kimin için:** aracı ilk kez kuran herkes. **Hedef:** kendi Wazuh'unuzdan alınmış ve alan alan kontrol
ettiğiniz bir rapor. Demo için 10 dakika, gerçek bağlantı için 30–60 dakika ayırın.

Önce demoyu çalıştırın. Demo her sayfayı sentetik veriyle gösterir; böylece kendi Wazuh'unuz, sertifikalarınız
ve hesaplarınız devreye girmeden önce sağlıklı bir kurulumun nasıl göründüğünü bilirsiniz.

## Gereksinimler

| Ne | Demo | Gerçek Wazuh |
|---|---|---|
| Docker ve Compose | evet | evet (ya da Kubernetes: [Kubernetes](Kubernetes-TR)) |
| 9200 portundan erişilebilen Wazuh Indexer | – | evet |
| 55000 portundan erişilebilen Wazuh sunucu API'si | – | isteğe bağlı; yoksa ajan/daemon sağlığı, kural bilgisi ve logtest çalışmaz |
| Araç (fonksiyon) çağırabilen bir model | – (`mock`) | evet: barındırılan ya da yerel |
| Wazuh kök CA dosyası | – | evet (sertifikalar genel güvenilir değilse) |

## Adım 1 — Demoyu başlatın

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git
cd wazuh-daily-triage
cp .env.demo .env
docker compose up -d --build
```

**Beklenen:** `docker compose ps` çıktısında `wazuh-daily-triage` çalışıyor, yaklaşık yarım dakika sonra da
"healthy" görünür. `curl -fsS http://127.0.0.1:8080/healthz` HTTP 200 döner.

**Olmadıysa:** nedeni `docker compose logs triage` gösterir. En sık görülen neden, `.env.example` kopyasına
`WDT_DEMO=true` satırının başka bir `WDT_DEMO=` satırının üstüne eklenmesidir; son satır geçerli olur.
`.env.demo` dosyasını değiştirmeden kullanın.

## Adım 2 — Giriş yapın

<http://127.0.0.1:8080> adresini açın ve `demo-password-change-me` ile girin (`.env.demo` içindeki
`APP_PASSWORD`).

**Beklenen:** eğilim çizgili ana göstergeler, alarm hacmi grafiği, ATT&CK taktik şeridi ve bitmiş bir rapor, açık
sorular ve bekleyen önerilerle iş listesini gösteren **Nöbet panosu**.

**Olmadıysa:** giriş tekrar giriş sayfasına dönüyorsa düz HTTP üzerinde `COOKIE_SECURE=true` vardır.
`.env.demo` bunu `false` yapar; değiştirmediğinizden emin olun.

## Adım 3 — Demo verisiyle bir koşu başlatın

Panoda (sağ üstte) ya da kenar çubuğundaki ortamın **Raporlar** sayfasında **Şimdi kontrol et** düğmesine basın.

**Beklenen:** düğme önce çalışıyor durumuna geçer, sonra raporu açma bağlantısını gösterir. Demo `mock`
sağlayıcısını kullanır: model çağırmadan yer tutucu bir rapor yazar; koşu saniyeler sürer ve maliyeti yoktur.

## Adım 4 — Raporu ve öneri kutusunu inceleyin

1. Raporu açın. Yukarıdan aşağıya: özet, altyapı, bulgular, asistanın soruları, ardından yapay zekâdan
   bağımsız deterministik sorguların yer aldığı veri bölümü.
2. **Öneriler** sayfasını açın. Bir bulgu için karar verin, bir soruyu cevaplayın.
3. **Bilgi tabanı**nı açın ve cevabınızın orada durduğunu görün.

Bu sayfaların her biri [Kullanıcı rehberi](User-Guide-TR)nde anlatılır. Aynı sentetik veride gerçek bir modeli
denemek için `.env` içinde `LLM_*` değişkenlerini ayarlayıp `docker compose up -d` komutunu yeniden çalıştırın.

## Adım 5 — Salt okunur Wazuh hesaplarını oluşturun

Yönetici kimlik bilgilerini kullanmayın. İki hesabı
[docs/permissions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md)
içindeki komutlarla oluşturun:

| Hesap | Nerede | Yetkisi |
|---|---|---|
| `daily-triage` | Indexer | `wazuh-alerts-*` ve `wazuh-states-vulnerabilities-*` okuma; `daily-triage-*` (kendi verisi) üzerinde tam yetki |
| `daily-triage` | Wazuh API (isteğe bağlı) | ajanları, manager durumunu, cluster durumunu, kural dosyalarını okuma; logtest çalıştırma |

**Beklenen:** Indexer bloğunun sonundaki doğrulama bir sayı döner:

```sh
curl -sS --cacert root-ca.pem -u 'daily-triage:PAROLA' "https://<indexer>:9200/wazuh-alerts-*/_count"
```

**Olmadıysa:** `401` yanlış parola ya da eksik rol eşlemesidir. `403` eksik indeks yetkisidir. wazuh-docker ve
wazuh-kubernetes kurulumlarında REST API ile oluşturulan kullanıcılar, `securityadmin` YAML dosyalarını yeniden
yüklediğinde silinebilir; aynı tanımları o dosyalara da ekleyin (yetki belgesi nasıl yapılacağını anlatır).

## Adım 6 — Kurulumu kendi Wazuh'unuza bağlayın ve bağlantıları test edin

Demo yapılandırmasını bırakıp örnek dosyadan başlayın:

```sh
cp .env.example .env
openssl rand -hex 32          # çıktıyı APP_SECRET olarak kullanın
mkdir -p config/certs
cp /path/to/root-ca.pem config/certs/root-ca.pem
vi .env
```

Tek ortam için en küçük `.env` [Kurulum](Installation-TR) sayfasında (A2 bölümü), bütün değişkenler
[Yapılandırma](Configuration-TR) sayfasındadır. Sonra:

```sh
docker compose up -d
docker compose exec triage python -m app.check
```

`python -m app.check` koşu başlatmadan Indexer'ı (alarmlar, zafiyetler, uygulamanın kendi indeksleri), Wazuh
API'yi, varsa ek kaynakları ve modeli test eder. `--no-llm` model çağrısını atlar. Aynı test ortamın **Raporlar** sayfasındaki
bağlantı testi düğmesidir.

**Beklenen:** bütün kontroller geçer. Geçmeyeni devam etmeden düzeltin: yarım çalışan bir bağlantıyla alınan
raporda kör noktalar olur.

**Olmadıysa:** [Sorun giderme](Troubleshooting-TR) sayfasına bakın. Sık nedenler: CA dosyası (konteyner
içindeki yol `/app/config/certs/…`), Wazuh parola kuralını karşılamayan API parolası ve üretim modunda açılmayı
reddeden konteyner. Log satırı değişkenin adını verir.

## Adım 7 — İlk gerçek koşu

**Şimdi kontrol et** düğmesine basın. Daha önce rapor yoksa pencere yapılandırılmış en küçük değerdir
(`window_min_hours`); ikinci koşudan itibaren "son başarılı koşudan beri" olur.

**Beklenen:** birkaç dakika içinde bir rapor. Süre modele ve `max_tool_steps` değerine bağlıdır.

## Adım 8 — Rapora güvenmeden önce kontrol edin

| Bakılacak yer | Görmeniz gereken | Görmüyorsanız |
|---|---|---|
| Pencere | beklediğiniz dönem | başarısız bir koşu pencereyi ilerletmez; sonraki koşu son başarılı koşudan başlar |
| Altyapı | indexer durumu, disk, ajanlar, daemon'lar | ajan ve daemon alanları boşsa Wazuh API tanımlı değildir ya da yetkisi yoktur |
| Seviye dağılımı, en sık kurallar | aynı dönem için Wazuh panonuzdaki sayılarla uyumlu değerler | `alerts_index` ve saat dilimini (`TZ`) kontrol edin |
| Toplama hataları (kör nokta) | olmamalı | her satır başarısız olmuş bir sorgudur; ait olduğu bölüm "temiz" değil, boştur |
| Bulgular | her biri kanıt ve etiketle | rapor yalnız sağlık bayraklarını listeliyorsa model başarısız olmuştur; özet bunu söyler |
| Yapay zekânın araç çağrıları | sıfırdan büyük bir sayı | sıfır çağrı çoğunlukla modelin araç çağırmayı desteklemediğini gösterir |

Sonra demodaki üç işi tekrarlayın: bir bulguya karar verin, bir soruyu cevaplayın ve ikisini de bilgi
tabanında bulun. Sonraki koşu bunları okur.

## Sonraki adımlar

- Üretime almadan önce: [Güvenlik kontrol listesi](Security-Checklist-TR).
- Modele ne gider, ne gitmez: [Gizlilik](Privacy-TR), [Güvenlik modeli](Security-Model-TR).
- AI turları arasında acil uyarılar: [Nöbet](Watch-TR).
- Birden fazla Wazuh: [Kurulum](Installation-TR) (A3) ve [Yapılandırma](Configuration-TR).

*0.11.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](Getting-Started) · [Türkçe](Getting-Started-TR)
