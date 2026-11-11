# Örnek senaryolar

**Kimin için:** parçaların birlikte nasıl çalıştığını görmek isteyen yeni kullanıcılar. Buradaki bütün veriler
uydurmadır: sunucu adları hayalîdir, IP adresleri dokümantasyon aralıklarındandır (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`). Eşikler varsayılan değerlerdir; sizinkiler farklı olabilir.

## 1. SSH kaba kuvvet denemesinin ardından başarılı giriş

**Ne olur.** `web01`, `203.0.113.45` adresinden başarısız SSH girişleri alır; ardından aynı adresten bir giriş
başarılı olur.

**Nöbet** (açıksa), öncesindeki `brute_window_minutes` içinde en az `brute_failures` başarısız denemesi olan
bir adresten başarılı giriş görür. Bu tetikleyici her zaman kritiktir; sessiz saatlerde bile "kural tabanlı
uyarı — yapay zekâ incelemedi" başlığıyla gönderilir.

**Sonraki AI turu** olayları ilişkilendirir, kaynak adresin profilini çıkarır, nöbet olayına hüküm verir ve
çoğunlukla sorar: *bu giriş sizin miydi?*

**Siz** soruyu cevaplarsınız. "Evet, yeni VPN çıkışı" cevabı bilgi tabanı kaydı olur ve o adresten aynı örüntü
bir dahaki sefere bağlamdır. "Hayır" cevabı bunu gerçek olay yapar: bulgudan olay kaydı oluşturun.

## 2. Bir ajan veri göndermeyi bırakır

**Ne olur.** `db02` üzerindeki ajan gece kopar.

**Nöbet** bunu `agent_minutes` sonra duyurur; aynı anda beş ve üstü kritiktir. **Günlük rapor** pasif ajanları
ve envanter listesi varsa beklenen ama eksik ajanları listeler.

**Siz** sunucuya bakarsınız. Makine hizmetten çıkarıldıysa ajanı Wazuh'tan silin ya da adını `ignore_agents`
listesine ekleyin; böylece kapsam hesabına girmez.

## 3. Indexer diski doluyor

**Ne olur.** Indexer düğümündeki disk kullanımı uyarı eşiğini geçer.

**Günlük rapor**, `disk_warn_percent` (varsayılan 75) değerinden itibaren sağlık bayrağı kaldırır. Birkaç
dakikada bir modelsiz çalışan **canlılık kontrolü** yüzde 90'da bildirir, sürdükçe hatırlatır ve düzelince
haber verir.

**Siz** alarmlar indekslenmez hâle gelmeden önce harekete geçersiniz: saklama süresi, depolama ya da en
gürültülü kurallar ([gürültü haritası](User-Guide-TR)). Kesinti yaşanırsa aylık denetim raporunda görünür.

## 4. Daha önce görülmemiş bir kural ID'si

**Ne olur.** Bir ajan güncellemesinden sonra, son 14 günde tetiklenmemiş bir kural tetiklenir.

**Rapor** bunu 14 günde ilk kez görülen kurallar arasında listeler; anomali denetimi de yeni kural–ajan
çiftlerini işaretler. Model önce buna bakar, çünkü hem saldırılar hem yanlış yapılandırmalar yeni olanda ortaya
çıkar.

**Siz** karar verirsiniz: güncellemeden sonra beklenen bir durum (durum *Bilinen gürültü (baseline)*, onu
anormal yapacak koşulla birlikte) ya da incelenecek bir konu.

## 5. Alarm hacmi sıçrıyor

**Ne olur.** Bir tarayıcı genel web sunucunuzu bulur; alarmlar katlanır.

**Nöbet**, bir aralıkta 24 saatlik ortalamanın en az `spike_factor` katı ve en az `spike_min` alarm olduğunda
*ani artış* tetikleyicisini çalıştırır. **Rapor** önceki pencereyle karşılaştırır ve artışı hangi kuralların ve
ajanların taşıdığını gösterir.

**Siz** AI turundan sonra hükmü okursunuz. Bildik tarayıcı gürültüsüyse o olay anahtarını susturma ya da eşiği
yükseltme önerisini kabul edin. Öneri, siz kabul edene kadar hiçbir şeyi değiştirmez.

## 6. Yanlış pozitifi öğretmek

**Ne olur.** Her gece bir yedekleme işi `backup01` üzerinde "çoklu kimlik doğrulama hatası" kuralını tetikler.
Model bunu *İncelenecek* olarak raporlar.

**Siz** bulguyu **Öneriler**'de açar, *Bilinen gürültü (baseline)* seçer ve yazarsınız: "gecelik yedekleme işi,
02:00–02:30, servis hesabı svc-backup; bu pencerenin dışındaysa ya da başka sunucudan geliyorsa anormal".

**Sonraki koşular** bu kaydı bağlam olarak alır. Model gecelik patlamayı artık raporlamaz; not ise neyin hâlâ
raporlanmaya değer olduğunu söyler. Nöbet, kritik olaylar dışında, o kural için bildirim göndermeyi bırakır.

## 7. Test edilen ve canlıda kanıtlanan bir kural taslağı

**Ne olur.** Model, gecelik yedekleme hatalarını seviye 10'dan seviye 4'e düşüren, `backup01` ve servis
hesabıyla sınırlı bir alt kural önerir.

1. **What would it do?**, 14 günde 420 alarmı devralacağını, hepsinin `backup01`'den geldiğini ve başka
   sunucudan yüksek seviyeli alarm almadığını gösterir.
2. Taslak seviye düşürdüğü için **Approve and deploy** kural ID'sini yazmanızı ister.
3. Uygulama kuralı yazar, doğrular, manager'ı yeniden başlatır ve iki örneği çalıştırır: yedekleme hatası yeni
   kuralla eşleşmeli, başka sunucudan gelen hata eşleşmemelidir.
4. Bir gün sonra **Check live** canlıda 14 kez doğrulandığını gösterir. Görülmedi deseydi kural yüklenmiş ama
   eşleşmiyor olurdu; yeniden oynatma sayıları da eşleşmesi gerektiğini söylerdi.
5. **Make permanent**, kendi kural deponuz için paketi verir.

Tam prosedür ve hata durumunda olanlar: [Kural yaşam döngüsü](Rule-Lifecycle-TR).

*0.11.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](Scenarios) · [Türkçe](Scenarios-TR)
