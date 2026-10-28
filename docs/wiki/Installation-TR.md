# Kurulum

Üç desteklenen çalıştırma yolu var. Hepsi aynı konteyner imajını ve aynı yapılandırma dosyalarını kullanır;
birini seçin ve [Yapılandırma](Configuration-TR) sayfasıyla devam edin.

| Yol | Ne zaman | Süre |
|---|---|---|
| Docker Compose | VM, all-in-one Wazuh veya ilk deneme | 5–15 dk |
| Kubernetes (Helm veya Kustomize) | Wazuh zaten kümede çalışıyorsa | 15–30 dk |
| Yerel Python | geliştirme veya kodu hızlıca görmek | 5 dk |

## Başlamadan önce

1. **Wazuh erişimi.** Indexer (9200) zorunlu; Wazuh API (55000) isteğe bağlıdır ama ajan, servis, kural ve
   logtest kontrollerini açar. [docs/permissions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/permissions.md) sayfasındaki **salt okunur** hesapları
   oluşturun — admin kimlik bilgisi kullanmayın.
2. **Model.** Anthropic anahtarı, OpenAI uyumlu herhangi bir uç nokta veya yerel model (Ollama, vLLM, LM Studio).
   `LLM_PROVIDER=mock` yalnızca demo içindir.
3. **TLS.** Arayüzde parola ve imzalı çerez var; HTTPS arkasında yayınlayın, paylaşılan ağda düz HTTP
   kullanmayın.
4. **Ağ.** Konteyner Indexer ve API'ye, ayrıca model uç noktasına HTTPS ile erişebilmelidir. Wazuh kendinden
   imzalı sertifika kullanıyorsa CA'yı `./config/certs/` altına kopyalayıp `ca_file` ayarlayın.

## Seçenek A — Docker Compose

### A1. Demo (Wazuh ve model gerekmez)

```sh
git clone https://github.com/dururustem68/wazuh-daily-triage.git
cd wazuh-daily-triage
cp .env.example .env
```

`.env` içinde:

```sh
WDT_DEMO=true
LLM_PROVIDER=mock
APP_PASSWORD=uzun-bir-demo-parolasi
```

```sh
docker compose up -d --build
```

<http://127.0.0.1:8080> adresini açın, giriş yapın ve bir kez **Run check now** düğmesine basın. Demo
`config/demo.yaml` ve sentetik veri kullanır; Wazuh'a bağlanmaz. `WDT_DEMO=true` ile
`ENVIRONMENT=production` birlikte kullanılamaz — uygulama açılmaz. Yerel derleme yerine **hazır 0.7.0 imajını**
çalıştırıyorsanız ayrıca `WDT_CONFIG=config/demo.yaml` verin (0.7.0 sonrasında düzeltildi).

### A2. Gerçek Wazuh (tek ortam)

`docker-compose.yml` portu yalnızca `127.0.0.1` üzerinde yayınlar, `./config` dizinini salt okunur ve `./logs`
dizinini denetim kaydı için bağlar. Örnek dosyadan başlayın:

```sh
cp .env.example .env
openssl rand -hex 32        # APP_SECRET
```

Asgari `.env`:

```sh
ENVIRONMENT=production
APP_PASSWORD=<güçlü ve benzersiz parola>
APP_SECRET=<openssl çıktısı>
COOKIE_SECURE=true
FORWARDED_ALLOW_IPS=172.16.0.0/12

LLM_PROVIDER=anthropic
LLM_MODEL=<model kimliği>
LLM_API_KEY=<anahtar>

WAZUH_ENV_NAME=Production
WAZUH_INDEXER_URL=https://wazuh-indexer.example.internal:9200
WAZUH_INDEXER_USER=daily-triage
WAZUH_INDEXER_PASSWORD=<indexer parolası>
WAZUH_API_URL=https://wazuh-manager.example.internal:55000
WAZUH_API_USER=daily-triage
WAZUH_API_PASSWORD=<api parolası>
WAZUH_CA_FILE=/app/config/certs/root-ca.pem
```

`FORWARDED_ALLOW_IPS`, **konteynerin** proxy'yi gördüğü adres olmalıdır. Host üzerindeki bir proxy, yayınlanan
`127.0.0.1:8080` adresine bağlandığında konteynere `127.0.0.1`'den değil Docker köprü ağ geçidinden (ör.
`172.18.0.1`) gelir; `docker network inspect <proje>_default` ile bakıp aralığı bu adrese daraltın. Yanlışsa
yönlendirme başlıkları yok sayılır: giriş sınırlaması ve denetim kaydında herkes tek IP görünür. Asla `*`
kullanmayın.

CA'yı kopyalayın:

```sh
mkdir -p config/certs
cp /yol/root-ca.pem config/certs/root-ca.pem
```

Sonra:

```sh
docker compose up -d
docker compose exec triage python -m app.check
```

`python -m app.check [ortam…] [--no-llm]` (veya ortam sayfasındaki **Test connections**) Indexer'ı (alarm,
zafiyet ve depolama indeksleri), API'yi, yapılandırılmış ek kaynakları ve modeli koşu başlatmadan doğrular.
Bildirimlerin kendi **Test notification** düğmesi vardır.

> `.env` içindeki yorumlar kendi satırında olmalıdır: `docker compose`, değer satırında `#` sonrasını değerin
> parçası sayar.

> **Üretimde imajı sabitleyin.** `docker-compose.yml` demoyu kolaylaştırmak için `:latest` kullanır. Üretimde
> `ghcr.io/dururustem68/wazuh-daily-triage:0.7.0` (veya kendi digest'inizi) yazın; böylece yükseltme bilinçli
> bir adım olur.

### A3. Birden çok Wazuh ortamı

YAML dosyasını oluşturun; konteyner `./config` dizinini zaten bağlar:

```sh
cp config/environments.example.yaml config/environments.yaml
mkdir -p config/context config/seed
cp config/context/example.md config/context/prod.md
vi config/environments.yaml
```

`config/environments.yaml` varsa `WAZUH_*` tek-ortam değişkenleri yok sayılır ve tüm ortamlar YAML'dan gelir.
Parolalar `.env` içinde `${DEGISKEN}` olarak kalır ve açılışta genişletilir. Tam şema için
[Yapılandırma](Configuration-TR) sayfasına bakın.

### A4. Yerel model (alarm verisi ağdan çıkmaz)

`docker-compose.yml` isteğe bağlı bir Ollama profili içerir:

```sh
docker compose --profile ollama up -d
docker exec -it ollama ollama pull qwen3:14b
```

```sh
# .env
LLM_PROVIDER=openai
LLM_BASE_URL=http://ollama:11434/v1
LLM_MODEL=qwen3:14b
```

Sonra `triage` konteynerini yeniden başlatın. Rapor kalitesi modele bağlıdır: küçük modeller araç çağrılarını
atlamaya ve daha zayıf bulgular üretmeye eğilimlidir; istemleri ayarlamadan önce daha büyük bir model deneyin.
Yerel modelde alarm içeriği ana makineden çıkmaz — düzenlemeye tabi ortamlarda genellikle belirleyici olan budur.

## Seçenek B — Kubernetes

Helm chart ve Kustomize temeli aynı sertleştirilmiş podu kurar: tek replika, root olmayan kullanıcı, salt
okunur kök dosya sistemi, PVC yok (durum Wazuh Indexer'da), `/healthz` liveness ve `/readyz` readiness.

### B1. Helm

```sh
helm repo add wazuh-daily-triage https://dururustem68.github.io/wazuh-daily-triage
helm repo update
```

`my-values.yaml`:

```yaml
secret:
  APP_PASSWORD: "..."
  APP_SECRET: "..."            # openssl rand -hex 32
  LLM_API_KEY: "..."
  INDEXER_PASSWORD: "..."
  API_PASSWORD: "..."

app:
  cookieSecure: true
  forwardedAllowIPs: "10.0.0.0/8"   # ingress denetleyicisinin pod CIDR'ı, asla "*"
```

```sh
helm install wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --version 0.1.3 -f my-values.yaml
```

Depodan doğrudan: `helm install wazuh-daily-triage ./deploy/helm/wazuh-daily-triage -f my-values.yaml`.

`secret:` altındaki her anahtar podda ortam değişkenine dönüşür; `VIEWER_PASSWORD`, `MCP_TOKEN` ve
`METRICS_TOKEN` da oraya gider. Gizli olmayan anahtarlar (`AUTH_DISABLED`, `LOG_LEVEL`, `ADMIN_ENVS`, …)
`env:` altına yazılır. Uygulama yapılandırması (`config.environments`) `${VAR}` yer tutucuları içeren tam bir
`environments.yaml`'dır.

### B2. Kustomize

```sh
cp -r deploy/kubernetes/example ~/triage-overlay
cd ~/triage-overlay
# depo dışında göreli "../base" çözülmez — sürümü sabitlenmiş uzak base'i gösterin:
sed -i 's#^  - ../base.*#  - https://github.com/dururustem68/wazuh-daily-triage//deploy/kubernetes/base?ref=v0.7.0#' kustomization.yaml
cp secret.env.example secret.env
vi secret.env environments.yaml context.md
kubectl apply -k .
kubectl -n wazuh-daily-triage rollout status deploy/wazuh-daily-triage
kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage -- python -m app.check
```

`deploy/kubernetes/components/` altındaki isteğe bağlı bileşenler: `networkpolicy`, `ingress-nginx`,
`ingress-traefik-authentik`, `rbac-readonly`. Ayrıntılar:
[deploy/kubernetes/README.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/kubernetes/README.md).

> **Yalnızca tek replika.** Zamanlayıcı süreç içinde çalışır; ikinci replika her kontrolü iki kez çalıştırır.
> Deployment bu yüzden `Recreate` stratejisini kullanır. Ek replikaları yalnızca erişilebilirlik için
> çalıştıracaksanız `WDT_SCHEDULER=false` ayarlayın.

## Seçenek C — Yerel Python

```sh
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# demo
WDT_DEMO=true APP_PASSWORD=demo uvicorn app.main:app --reload

# gerçek yapılandırma
WDT_CONFIG=config/environments.yaml APP_PASSWORD=... uvicorn app.main:app --reload
```

Uygulama `.env` dosyasını **kendisi okumaz**; değişkenleri dışa aktarın (veya `env_file` ile geçen Docker'ı
kullanın). Python 3.11–3.13 desteklenir; `tzdata` saat dilimi veritabanını kurar, böylece slim imajlarda da
`TZ` çalışır.

## TLS ve ters vekil (reverse proxy)

Önüne TLS sonlandıran herhangi bir vekil koyun; uygulama konteyner içinde `0.0.0.0:8080` dinler, compose onu
loopback'e yayınlar.

```caddy
triage.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

```nginx
server {
    listen 443 ssl;
    server_name triage.example.com;
    # ssl_certificate ...;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Sonra:

```sh
COOKIE_SECURE=true
FORWARDED_ALLOW_IPS=<vekil adresi veya CIDR>
```

`FORWARDED_ALLOW_IPS` uvicorn (`--proxy-headers`) tarafından okunur. Yalnızca vekili yazın: `*`, her istemcinin
`X-Forwarded-For` uydurmasına izin verir. Uygulamanın önüne SSO koyacaksanız
[SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR) sayfasıyla devam edin.

## Kurulumu doğrulama

```sh
curl -fsS http://127.0.0.1:8080/healthz     # liveness: süreç ayakta
curl -fsS http://127.0.0.1:8080/readyz      # readiness: açılış ve yapılandırma tamam
curl -fsS http://127.0.0.1:8080/metrics     # admin oturumu veya METRICS_TOKEN gerekir
```

- `/healthz` Wazuh'a hiç dokunmaz; Indexer arızası konteyneri yeniden başlatmamalıdır.
- `/readyz` de bilinçli olarak Indexer çağrısı yapmaz; böylece kesinti, kesintiyi açıklayan arayüzü ortadan
  kaldırmaz.
- İkisi de kimlik doğrulaması istemez ve probe'lar için güvenlidir.
- İlk giriş `APP_PASSWORD` ile yapılır; salt okunur rol açıksa giriş sayfası `VIEWER_PASSWORD`'dan söz eder.

Ardından:

1. Ortam sayfasını açıp **Test connections** düğmesine basın.
2. **Run check now** ile (veya zamanlamayı bekleyerek) bir raporun oluştuğunu doğrulayın.
3. Bir bulguyu onaylayın veya reddedin; **Knowledge base** sayfasında kararın saklandığını görün.
4. `logs/audit.jsonl` içinde giriş ve karar kaydını kontrol edin.

Başarılı açılış; ortamları, zamanlamayı, denetim dosyasını ve güvenlik uyarılarını loglar. Üretimde
`app/security.py` şu durumlarda **açılmayı reddeder**: `WDT_DEMO=true`, eksik veya örnek `APP_PASSWORD`, eksik
`APP_SECRET`, `VIEWER_PASSWORD`'ın admin parolasıyla aynı olması, `COOKIE_SECURE=false`, bir uç noktada TLS
doğrulamasının kapatılması veya `rule_deploy.enabled` için kimlik bilgisi eksikliği. İki bilinçli laboratuvar
istisnası için [docs/security-exceptions.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/docs/security-exceptions.md).

## Yükseltme ve geri dönüş

Uygulama durumsuzdur: raporlar ve bilgi tabanı Wazuh Indexer'daki (`daily-triage-*`) belgelerdir. Veritabanı
geçişi yoktur.

```sh
# Docker Compose (sabitlenmiş etiketle)
docker compose pull
docker compose up -d
docker compose exec triage python -m app.check

# Helm
helm upgrade wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --version 0.1.3 -f my-values.yaml
helm rollback wazuh-daily-triage 1     # gerekirse
```

Yükseltmeden önce [CHANGELOG.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/CHANGELOG.md) okuyun: yapılandırma anahtarları zaman zaman değişir.
Mevcut koşular aranabilir kalır; `run_retention_days` (YAML) yalnızca eski koşu belgelerini siler, bilgi tabanına
dokunmaz.

## Sorun giderme

| Belirti | Neden ve çözüm |
|---|---|
| Konteyner `refusing to start in production` ile çıkıyor | Mesaj değişkeni söyler. Gerçek `APP_PASSWORD`, `APP_SECRET`, `COOKIE_SECURE=true` ayarlayın veya TLS doğrulamasını düzeltin. |
| `FileNotFoundError: no config file and WAZUH_INDEXER_URL is not set` | Ne `config/environments.yaml` ne de `WAZUH_INDEXER_URL` var. Birini oluşturun. |
| Vekilden `502`, konteyner sağlıklı | Vekil yanlış porta (8080) ya da hosta gidiyor; `docker compose ps` kontrol edin. |
| Giriş sürekli `/login`'e dönüyor | Düz HTTP üzerinde `COOKIE_SECURE=true` veya vekil çerezleri siliyor. HTTPS kullanın; yerel testte geçici olarak `COOKIE_SECURE=false`. |
| `ZoneInfoNotFoundError` / bilinmeyen saat dilimi | `TZ`'yi IANA adı yapın (`Europe/Istanbul`) ve `tzdata` kurulu kalsın. |
| Wazuh'a TLS hatası | CA'yı `config/certs/` altına koyup `ca_file` (veya `WAZUH_CA_FILE`) ayarlayın; üretimde `verify_tls: false` kullanmayın. |
| Zamanlanan saatte rapor yok | Konteyner çalışıyor olmalı (zamanlayıcı süreç içinde), `schedule.enabled` açık olmalı ve saat dilimi `TZ` ile uyuşmalı. |
| Rapor içinde model hataları | **Test connections** çalıştırın; `LLM_*`, base URL ve token bütçesini (`max_tokens`) kontrol edin. |

Sonraki: [Yapılandırma](Configuration-TR) · [SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR) ·
[Görüntüleyici modu](Viewer-Mode-TR) · [MCP sunucusu](MCP-TR)

---

[English](Installation) · [Türkçe](Installation-TR)
