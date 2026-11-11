# Uyumluluk matrisi

**Kimin için:** aracın kendi ortamına uyup uymadığına karar verenler. Üç ifade sabit anlamlarla kullanılır:

- **Test edildi**: proje tarafından, sürekli entegrasyonda ya da geliştirildiği ortamda çalıştırılmıştır.
- **Bekleniyor**: kod yolu vardır ve bilinen bir engel yoktur, ama proje bunu çalıştırmamıştır.
- **Desteklenmiyor**: çalışmadığı bilinir ya da bilerek sunulmaz.

Otomatik testler canlı bir Wazuh cluster'ına karşı değil, yerleşik bir demo motoruna (sentetik veriyle küçük
bir OpenSearch sorgu motoru) karşı çalışır. Bu nedenle bir Wazuh sürümü için "test edildi", o sürüme karşı
geliştirmede kullanıldı demektir.

## Wazuh

| Bileşen | Durum | Not |
|---|---|---|
| Wazuh manager 4.14 | **Test edildi** | projenin geliştirildiği sürüm |
| 4.6'dan itibaren diğer Wazuh 4.x | Bekleniyor | 4.6 pratik alt sınırdır: isteğe bağlı dağıtım kullanıcısının RBAC eylemleri ve logtest API'si |
| 4.6 öncesi Wazuh 4.x | Salt okunur kullanım için bekleniyor | dağıtım yardımcılarının uç noktaları eksik olabilir |
| Diğer ana sürümler | beyan yok | denenmedi |
| Standart `wazuh-alerts-*` şablonuyla Wazuh Indexer (OpenSearch 2.x) | **Test edildi** | sorgular `bool.filter`, `terms`, `date_histogram`, `query_string` kullanır; eklenti gerekmez |
| Özel alarm indeksi adları | Bekleniyor | `alerts_index` bir desen ya da somut bir indeks alır |
| `wazuh-states-vulnerabilities-*` | isteğe bağlı | indeks yoksa zafiyet araçları boş sonuç döner |
| Tek sunucu, dağıtık cluster, wazuh-docker, wazuh-kubernetes | Bekleniyor | cluster'da `api.url` master'ı göstermelidir |

## Hangi özellik neye ihtiyaç duyar

| Özellik | Indexer | Wazuh API | Ek |
|---|---|---|---|
| Alarm analizi, günlük rapor, gürültü haritası, anomaliler | gerekli | – | – |
| Zafiyet özeti ve SLA | gerekli, zafiyet indeksi | – | – |
| Ajan ve daemon sağlığı, kapsam | – | salt okunur kullanıcı | – |
| Kural tanımları, ID çakışma denetimi, logtest | – | salt okunur kullanıcı | – |
| Nöbet | gerekli | "ajan koptu" tetikleyicisi için | bir bildirim kanalı |
| Kural dağıtımı | – | ayrı dağıtım kullanıcısı | manager yeniden başlatma izni |
| Depolama güvenliği politika denetimi | ISM okuma yetkisi (isteğe bağlı) | – | – |
| Prometheus, Loki, Kubernetes araçları | – | – | o kaynaklar; cluster okuma rolü |
| Olay biletleri | – | – | Zammad ya da Jira |
| MCP | kullanılan araçlara göre | kullanılan araçlara göre | `MCP_TOKEN` |

Wazuh API olmadan alarm analizi etkilenmez; raporun ajan, daemon ve kural bölümleri boş kalır.

## Çalışma ortamı

| Öğe | Durum |
|---|---|
| Python 3.11, 3.12, 3.13, 3.15 | **Test edildi** (CI matrisi); imaj 3.15 üzerine kuruludur |
| Python 3.14 | Bekleniyor (desteklenen aralıkta, matriste yok) |
| Python 3.10 ve öncesi | Desteklenmiyor |
| Linux konteyneri (yayımlanan imaj) | **Test edildi** |
| Windows ve macOS | Geliştirme için bekleniyor; kurulum hedefi değil |
| Helm chart | CI'da lint edilir, render edilir ve kurulur |
| Kustomize base ve bileşenleri | Bekleniyor; örnekler uyarlanmalıdır |
| Zamanlayıcı açıkken birden fazla replika | Desteklenmiyor: her kontrol iki kez çalışır |
| Güncel Chrome, Firefox, Edge, Safari | Bekleniyor; arayüz satır içi betik kullanmaz |

## Modeller

| Arayüz | Ayar | Gereklilik |
|---|---|---|
| Anthropic Messages API | `LLM_PROVIDER=anthropic` | araç kullanımı |
| OpenAI uyumlu Chat Completions (OpenAI, Azure OpenAI, Gemini, DeepSeek, Ollama, vLLM, LM Studio, LiteLLM) | `LLM_PROVIDER=openai` + `LLM_BASE_URL` | fonksiyon çağırma |
| Model yok | `LLM_PROVIDER=mock` | yalnız demo ve testler |

Test paketi mock sağlayıcıyı kullanır. Belirli bir modelin **sizin** alarmlarınızda ne kadar iyi olduğunu proje
sizin yerinize test edemez; `python -m app.eval` ile ölçün
([docs/eval.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/eval.md)). Model adları ve
parametre farkları: [docs/providers.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/providers.md).

## Entegrasyonlar

| Entegrasyon | Not |
|---|---|
| E-posta (SMTP, STARTTLS ya da SSL), Telegram, Microsoft Teams (Workflows webhook), Slack, Discord, ntfy, genel JSON webhook | herhangi bir birleşim |
| Zammad, Jira | olay biletleri, isteğe bağlı |
| Prometheus, Loki, Kubernetes API | salt okunur kaynaklar, isteğe bağlı |
| S3 uyumlu depolama | yedek hedefi, isteğe bağlı |
| SSO: Keycloak ile oauth2-proxy, Authentik forward auth | kullanıcı başlığı ekleyen bir proxy üzerinden |
| MCP istemcileri | `POST /mcp` üzerinde Streamable HTTP ya da stdio; protokol sürümleri `2025-06-18`, `2025-03-26`, `2024-11-05` |
| Arayüz dilleri | İngilizce, Türkçe, İspanyolca, Almanca |

## Bilinen sınırlar

- **Logtest, manager içi olayları yeniden oynatamaz** (rootcheck, FIM, SCA, zafiyet). Bu gruplara yönelik
  taslaklar logtest çalıştırılmadan dağıtılır ve gerçek bir olayda doğrulanmalıdır.
- **`rules:update`, Wazuh API'de tek dosyayla sınırlanamaz.** Dağıtım kullanıcısına bu yüzden özel kural
  dosyalarının geneli için güvenilir.
- **Pencere saklanan koşulara bağlıdır.** Koşu belgelerini silmek, sonraki koşunun varsayılan pencereye
  dönmesine yol açar.
- **Zamanlamayı tek süreç yapar.** Tek replika çalıştırın.
- **Maskeleme takma adlandırmadır, DLP değildir.** Serbest metindeki adlar ve e-posta olmayan kullanıcı adları
  algılanmaz.
- **Özel maskeleme desenleri**, `google-re2` kurulu değilse güvenli bir alt kümeyle sınırlıdır.
- **"What would it do?"**, CDB listelerini, zaman pencerelerini ve frekans kurallarını değerlendirmez.
- **Nöbetin "ani artış" tetikleyicisi** 24 saatlik ortalamayla karşılaştırır, günün saatini bilmez.
- **Yalnız iki rol.** Yönetici ve salt okunur görüntüleyici; paroladan ya da SSO gruplarından; daha ince rol yok.
- **ATT&CK görünümü kuralların `<mitre>` bloklarına bağlıdır.** Bloğu olmayan kuralların alarmları matriste yer
  almaz; alarmı olmayan bir taktik ölçülmüş bir kapsam boşluğu değil, bir ipucudur.
- **Nöbet olayları MCP üzerinden sunulmaz.**
- **Denetim izi** 20 MB'ta üç kuşakla döner ve uygulamanın biriminde durur.

Bu matrisin depodaki kopyası:
[docs/compatibility.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/compatibility.md).

*0.11.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](Compatibility) · [Türkçe](Compatibility-TR)
