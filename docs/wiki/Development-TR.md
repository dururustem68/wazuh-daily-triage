# Geliştirme ve katkı

**Kimin için:** katkı verenler. Bağlayıcı kurallar
[CONTRIBUTING.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/CONTRIBUTING.md) dosyasında;
modül haritası ve istek akışı
[docs/architecture.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/architecture.md)
belgesindedir.

## Temel kurallar

- **Wazuh'a karşı salt okunur.** Wazuh'u değiştiren bir özellik ayrı, açıkça yetkilendirilmiş bir bileşene
  aittir. Önce bir kayıt açıp tartışın.
- **Gerçek veri asla commit edilmez.** Testlerde, demo verisinde, örneklerde ve ekran görüntülerinde
  dokümantasyon IP aralıklarını (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) ve
  uydurma sunucu adlarını kullanın.
- **Önce deterministik.** Bir sorgunun hesaplayabildiği şey toplayıcıya aittir. Model yorumlar, saymaz.
- **Az bağımlılık.** Sağlayıcı SDK'sı yok, ön yüz derleme adımı yok.

## Yerel kurulum

```sh
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
WDT_DEMO=true APP_PASSWORD=x uvicorn app.main:app --reload
```

<http://127.0.0.1:8000> adresini açın. Demo modu Wazuh ve model istemez. Uygulama `.env` dosyasını kendisi
okumaz; değişkenleri kabukta dışa aktarın. Python 3.11 ya da üstü gerekir.

## Testler ve denetimler

CI'ın her push'ta Python 3.11, 3.12, 3.13 ve 3.15 için çalıştırdıkları:

```sh
ruff check .
pytest -q --cov=app --cov-report=term-missing
mypy
```

CI ayrıca bağımlılıkları denetler (`pip-audit`), Helm chart'ını lint ve render eder ve bir kind cluster'ına
kurar. Bir pull request önce yukarıdaki üç komutu yerelde geçmelidir.

## Demo motoru nasıl kullanılır

`app/demo.py` küçük bir OpenSearch sorgu motoru, sahte bir Wazuh API'si ve sentetik alarmlarla bir mock model
içerir. Test paketi de demo da bunun üzerinde çalışır; ikisi de cluster istemez. Değişikliğiniz demo motorunun
desteklemediği bir sorgu özelliği kullanıyorsa motoru genişletin ve test ekleyin. `app/demo_seed.py`, demonun
açıldığı örnek raporu, nöbet olaylarını ve ayarları sağlar.

## İstem ya da model değişikliğini ölçme

Testler kodun çalıştığını gösterir; teşhisin iyi olduğunu göstermez. İstemlere, araçlara ya da model işleyişine
dokunan değişikliklerde değerlendirmeyi cevabı bilinen vakalarla çalıştırın:

```sh
python -m app.eval config/eval/demo.yaml
python -m app.eval cases.yaml --repeat 3 --out results.json
```

Vaka başına recall, kaçırılanlar, olay diye raporlanan gürültü, araç adımları, belirteç ve süre raporlanır
([docs/eval.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/eval.md)). CI bunu
çalıştırmaz: bir model ve sizin veriniz gerekir.

## Yeni bir şey eklemek

| Eklenecek | Nereye |
|---|---|
| Model için bir araç | `app/agent/tools.py` içinde bir işleyici ve tanım; yeni alanlar `app/query_guard.py` izin listesine. MCP kendiliğinden sunar. Salt okunur olmalıdır |
| Bir veri kaynağı | `app/sources.py` içinde bir istemci, ortam çalışma zamanına kayıt, bir araç üzerinden sunum |
| Bir bildirim kanalı | `app/notify.py` içinde yapılandırma ve gönderici ([docs/notifications.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/notifications.md)) |
| Bir model sağlayıcısı | çoğu sağlayıcı OpenAI uyumlu istemciyle çalışır; farklı bir tel biçimi `app/llm/` altında yeni bir istemcidir |
| Bir nöbet tetikleyicisi | `app/watch.py`; model çağırmadan, yerelde karar vermelidir |

### Yeni bir arayüz dili

Arayüz metinleri `app/i18n.py` ve `app/i18n_v10.py` içindeki sözlüklerdir. Birebir aynı anahtarlarla bir sözlük
ekleyin (bir test bunu zorlar), `CATALOG`, `LANG_NAMES` ve `OUTPUT_LANGUAGE` içine kaydedin ve kodu
`app/config.py` içindeki `LANGUAGES` listesine ekleyin. Rapor dili ortamın `language` ayarını izler.

## Pull request'ler

- Her pull request tek konu ve testleriyle.
- Yeni kaynak dosyaları SPDX başlığıyla başlar:
  ```
  # SPDX-License-Identifier: AGPL-3.0-only
  # Copyright (C) 2026 <adınız>
  ```
- Commit'lerinizi imzalayın (`git commit -s`). Katkılar AGPL-3.0-only ile lisanslanır.
- Güvenlik sorunları kayıt ya da pull request olarak değil, özel olarak bildirilir.

## Dokümantasyon

- Wiki'nin kaynağı ana depodaki `docs/wiki/` dizinidir; wiki deposu bir kopyadır. Orada düzenleyip eşitleyin
  ([docs/wiki/README.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/wiki/README.md)).
- Her sayfanın İngilizce ve Türkçe sürümü vardır ve `_Sidebar.md` içinde listelenir.
- Sayfa kimin için olduğunu söyler, belirtilen sürümde çalıştırılmış komutlar verir ve sürüm ile gözden
  geçirme tarihiyle biter.
- "Test edildi", "bekleniyor" ve "desteklenmiyor" ifadelerini [Uyumluluk](Compatibility-TR) sayfasındaki
  anlamlarıyla kullanın.
- Tehlikeli işlemler etkisini, ön koşulunu, onayını ve geri alma yolunu belirtir.
- Ekran görüntüleri demodan alınır, asla gerçek bir ortamdan değil.

*0.11.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](Development) · [Türkçe](Development-TR)
