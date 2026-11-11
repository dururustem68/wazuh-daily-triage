# SSS, sözlük ve bilinen sınırlar

## Sık sorulan sorular

**Wazuh'un ya da Wazuh panosunun yerini mi alıyor?**
Hayır. Wazuh toplar, çözümler ve alarm üretir. Bu araç Wazuh'un ürettiğini okur, SIEM'in kendisinin ayakta
olduğunu denetler ve günlük incelemeyi bir kişi için hazırlar. Arama için panoyu kullanmaya devam edersiniz.

**SOAR mı? Kendiliğinden müdahale ediyor mu?**
Hayır. Adres engellemez, sunucu yalıtmaz, ajanlarda komut çalıştırmaz. Wazuh'ta yapabildiği tek değişiklik,
bir yöneticinin onayladığı kural taslağını dağıtmaktır; o da varsayılan olarak kapalıdır.

**Yapay zekâ Wazuh'ta kendi başına bir şey değiştirebilir mi?**
Hayır. Modelin araçları yalnız okur. Önerdiği şey, bir kişiyi bekleyen bir öneridir.

**Model sağlayıcısına ne gönderilir?**
Ortam tanımınız, bilgi tabanı, dönemin toplanan özeti (sayılar, gruplar, örnek log satırları) ve modelin
sorgularının sonuçları. İçindeki kişisel veri ve sırlar varsayılan olarak önce maskelenir. Siz aksini
seçmedikçe IP adresleri korunur. Bkz. [Gizlilik](Privacy-TR) ve [Güvenlik modeli](Security-Model-TR).

**Her şeyi kendi ağımda tutabilir miyim?**
Evet, OpenAI uyumlu uç nokta sunan yerel bir modelle (Ollama, vLLM, LM Studio). Raporun kalitesi modele
bağlıdır.

**Kendi veritabanına ihtiyacı var mı?**
Hayır. Raporlar, bilgi tabanı, nöbet olayları ve ayarlar Wazuh Indexer'ınızdaki belgelerdir. Bu aynı zamanda
bir indeks saklama kuralının onları silebileceği anlamına gelir: bkz. [Yedekleme](Backup-TR).

**Wazuh API olmadan çalışır mı?**
Alarm analizi için evet. Ajan ve daemon sağlığı, kural tanımları, logtest ve kural dağıtımı API ister.

**Model maliyetini nasıl denetim altında tutarım?**
Günde bir ya da iki AI turu, koşu başına araç adımı sınırı (`max_tool_steps`) ve hacminize uygun bir model.
Nöbet, canlılık kontrolü, gürültü haritası ve denetim raporu modeli hiç çağırmaz.

**Hangi modeli kullanmalıyım?**
Araç çağırması güvenilir olan bir model. Bunun ötesinde genel bir sıralamaya güvenmek yerine kendi incelediğiniz
günlerde `python -m app.eval` ile ölçün.

**Birden fazla Wazuh kurulumu tek örneği paylaşabilir mi?**
Evet. Her ortamın kendi bağlantısı, zamanlaması, bilgi tabanı, model ayarı ve takma adları vardır.

**İş arkadaşlarıma salt okunur erişim verebilir miyim?**
Evet: görüntüleyici parolasıyla ya da SSO arkasında onları `SSO_VIEWER_GROUPS` içindeki bir gruba koyarak
([Görüntüleyici modu](Viewer-Mode-TR)).

**Erişilebilirlik için iki replika çalıştırabilir miyim?**
Yalnız biri dışında hepsinde zamanlayıcı kapalıysa. Aksi hâlde her kontrol iki kez çalışır.

**ISO 27001 uyumlu ya da sertifikalı mı?**
Böyle bir iddia yoktur. Aylık denetim raporu, bir ISMS gözden geçirmesini izleme faaliyetinin kanıtı olarak
destekleyebilir; uygunluk bir aracın değil, kuruluşunuzun yönetim sisteminin özelliğidir.

**Bu proje Wazuh'un parçası mı?**
Hayır. Bağımsızdır ve Wazuh, Inc. ile bağlantısı yoktur. Lisans AGPL-3.0'dır: değiştirilmiş bir sürümü ağ
üzerinden kullanıcılara sunuyorsanız kaynak kodunu da sunmanız gerekir.

**Nereden yardım ister ya da hata bildiririm?**
[GitHub kayıtları](https://github.com/dururustem68/wazuh-daily-triage/issues). Güvenlik sorunları
[güvenlik bildirimleri](https://github.com/dururustem68/wazuh-daily-triage/security/advisories/new) üzerinden
özel olarak iletilir.

## Sözlük

| Terim | Anlamı |
|---|---|
| Ortam | kendi ayarlarıyla tek bir Wazuh kurulumu (Indexer ve isteğe bağlı API) |
| Koşu | bir ortam için tek bir toplama ve teşhis geçişi; sonucu rapordur |
| Pencere | koşunun kapsadığı dönem; varsayılan olarak son başarılı koşunun bitişinden itibaren |
| AI turu | zamanlanmış koşu; ayrıca önceki turdan beri oluşan nöbet olaylarına hüküm verir |
| Nöbet | birkaç dakikada bir, model çağırmadan acil durumları denetleyen yerel kurallar |
| Canlılık kontrolü | Wazuh'un kendisinin çalıştığına dair birkaç dakikada bir yapılan denetim: indexer, API, daemon'lar, gelen alarmlar |
| Sağlık bayrağı | SIEM hakkında deterministik bir bulgu: sessizlik, indexer durumu, disk, duran daemon ve benzeri |
| Bulgu | rapordaki tek bir konu; etiketi, önemi, kanıtı ve önerisiyle |
| Etiket | modelin sınıflandırması: gerçek olay, incelenecek, tespit boşluğu, yanlış pozitif, baseline artışı, ölçüm, beklenen, düzeltme |
| Hüküm | AI turunun bir nöbet olayı hakkındaki kararı: gerçek olay, incelenecek, beklenen ya da gürültü |
| Öneri kutusu | karar bekleyen bulgular; tek tek ve yinelenmeden |
| Bilgi tabanı | kurulumun hatırladığı ve her koşuda modele verdiği bilgiler |
| Baseline | bilinen, olağan gürültüyü tanımlayan bilgi tabanı kaydı |
| Öneri (proposal) | bir modelin önerdiği bilgi tabanı kaydı; onaylanana kadar etkisiz |
| Kural taslağı | bilgi tabanında saklanan, önerilmiş bir Wazuh kuralı |
| Dağıtım (deploy) | onaylanmış taslağın Wazuh API üzerinden manager'a yazılması (isteğe bağlı) |
| Canlı doğrulama | bir kuralın uygulandıktan sonra gerçek olaylarla eşleştiğinin denetlenmesi |
| Kalıcı hâle getirme (promotion) | dağıtılmış taslağın kendi kural dosyanıza ya da deponuza taşınması |
| Depolama öneki | uygulamanın indekslerinin ad öneki; varsayılan `daily-triage` |
| Maskeleme, takma ad | kişisel verinin modele ulaşmadan önce `<email:3f9a…>` gibi kararlı bir belirteçle değiştirilmesi |
| Maskeleme profili | standart algılayıcılar ve Ayarlar'dan yönetilen kendi algılayıcılarınız |
| Sorgu sınırları (query guard) | her model ya da MCP sorgusunun geçmesi gereken sınırlar: alanlar, zaman aralığı, sonuç boyutu |
| MCP | Model Context Protocol; kendi yapay zekâ asistanınızın salt okunur araçları kullanmasını sağlar |
| Görüntüleyici | salt okunur rol (görüntüleyici parolası ya da `SSO_VIEWER_GROUPS` içindeki bir SSO grubu) |
| ATT&CK taktiği / tekniği | MITRE'nin saldırganın amacı (Credential Access) ve yöntemi (T1110 Brute Force) için adları; Wazuh kuralları bunları bir `<mitre>` bloğunda taşır |
| Denetim izi | durum değişikliklerinin yalnız sona eklenen, özet zincirli dosyası; aylık denetim raporu değildir |

## Bilinen sınırlar

Liste [Uyumluluk](Compatibility-TR) sayfasında, *Bilinen sınırlar* başlığı altında tutulur.

*0.11.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](FAQ) · [Türkçe](FAQ-TR)
