# Kubernetes ve Helm: üretim rehberi

**Kimin için:** uygulamayı bir cluster'da çalıştıran platform mühendisleri. İlk bakış için `port-forward`
yeterlidir; bu sayfa başkalarının güveneceği bir kurulum içindir. Chart başvurusu:
[Helm chart README](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/helm/wazuh-daily-triage/README.md);
Kustomize: [deploy/kubernetes/README.md](https://github.com/dururustem68/wazuh-daily-triage/blob/main/deploy/kubernetes/README.md).

## Ne kurulur

**Tek replikalı** bir Deployment (strateji `Recreate`), 8080 portunda bir Service, bir Secret,
`environments.yaml` içeren bir ConfigMap ve isteğe bağlı olarak Ingress, NetworkPolicy ve salt okunur bir
ClusterRole. Pod root olmayan kullanıcıyla (uid 10001), salt okunur kök dosya sistemiyle ve bütün yetenekler
düşürülmüş olarak çalışır. PersistentVolumeClaim yoktur: raporlar ve bilgi tabanı Wazuh Indexer'ınızdaki
belgelerdir.

| Probe | Yol | Anlamı |
|---|---|---|
| liveness | `/healthz` | süreç cevap veriyor; hiçbir bağımlılığa dokunulmaz |
| readiness | `/readyz` | açılış ve yapılandırma tamam; ağ çağrısı yok |

İki probe da bilerek Wazuh'u çağırmaz. Readiness bir SIEM kesintisinde başarısız olsaydı, Kubernetes kesintiyi
açıklayan tek sayfayı devreden çıkarırdı.

## Helm ile kurulum

```sh
helm repo add wazuh-daily-triage https://dururustem68.github.io/wazuh-daily-triage
helm repo update
helm install wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --namespace wazuh-daily-triage --create-namespace \
  --version 0.3.0 -f my-values.yaml
```

Chart 0.3.0, uygulamanın 0.11.0 sürümünü kurar. Üretimde önemli değerler:

| Değer | Ne yazılır |
|---|---|
| `secret.*` | her anahtar bir ortam değişkeni olur: `APP_PASSWORD`, `APP_SECRET`, `LLM_API_KEY`, `INDEXER_PASSWORD`, `API_PASSWORD` ve kullanılıyorsa `VIEWER_PASSWORD`, `MCP_TOKEN`, `METRICS_TOKEN` |
| `env.*` | sır olmayan anahtarlar: `ENVIRONMENT: production`, `AUTH_DISABLED`, `ADMIN_ENVS`, `LOG_LEVEL` gibi |
| `config.environments` | eksiksiz bir `environments.yaml`; sırlar `${VAR}` yer tutucusuyla |
| `app.cookieSecure` | TLS arkasında `true` |
| `app.forwardedAllowIPs` | ingress controller'ın pod CIDR'ı; asla `*` |
| `app.notifyUiUrl` | genel adres; bildirimlerdeki bağlantı olarak kullanılır |
| `ingress.enabled`, `ingress.className`, `ingress.hosts`, `ingress.tls` | kendi ingress'iniz |
| `networkPolicy.ingressNamespace` | **kendi** ingress controller'ınızın ad alanı |
| `networkPolicy.wazuhNamespace` / `networkPolicy.wazuhCIDR` | Indexer ve API'nin yeri: cluster içinde bir ad alanı ya da dışarıda bir adres |
| `rbac.create`, `rbac.namespaces` | Kubernetes araçları için salt okunur ClusterRole; kullanmıyorsanız `false` |

Parolaları git'teki bir values dosyasına koymak yerine mevcut sır mekanizmanızı (External Secrets, Sealed
Secrets, SOPS) tercih edin.

## Kustomize ile kurulum

Örnek overlay'i kopyalayın, sabitlenmiş uzak base'e yönlendirin ve gereken bileşenleri ekleyin
(`networkpolicy`, `ingress-nginx`, `ingress-traefik-authentik`, `rbac-readonly`). Komutlar
[Kurulum](Installation-TR) sayfasının B2 bölümündedir. `secret.env` değişince `kubectl apply -k .` yeni adlı
bir Secret üretir ve pod onunla yeniden başlar.

## Doğrulama

```sh
kubectl -n wazuh-daily-triage rollout status deploy/wazuh-daily-triage
kubectl -n wazuh-daily-triage logs deploy/wazuh-daily-triage | head -50
kubectl -n wazuh-daily-triage exec deploy/wazuh-daily-triage -- python -m app.check
kubectl -n wazuh-daily-triage port-forward svc/wazuh-daily-triage 8080:8080
```

**Beklenen:** rollout tamamlanır, log yapılandırılmış ortamları ve zamanlamayı güvenlik uyarısı olmadan
listeler ve bütün bağlantı kontrolleri geçer. Sonra [Başlangıç](Getting-Started-TR) sayfasının 7. adımından
devam edin.

## Ağ politikası

Chart'ta 0.10'dan beri varsayılan olarak açıktır. Politika, release'in ad alanındaki bütün pod'ları seçer; bu
yüzden uygulamayı kendi ad alanına kurun. Gelen: pod'a yalnız ingress controller'ın ad alanı erişebilir. Giden:
DNS, Wazuh Indexer (9200) ve API (55000), model ve webhook'lar için HTTPS (443), SMTP (587, 465).

Şunlar için giden kuralını kendiniz ekleyin:

- kaynak olarak tanımlıysa Prometheus ve Loki;
- Kubernetes araçları açıksa Kubernetes API (çoğunlukla control-plane düğümlerinde 6443);
- cluster içinde başka portta sunulan model (Ollama: 11434);
- 443 dışındaki portta bir S3 uç noktası.

Engellenmiş giden trafik, `python -m app.check` çıktısında reddedilen bağlantı olarak değil, zaman aşımı olarak
görünür.

## Ingress ve SSO

| Düzen | Ayarlar |
|---|---|
| TLS arkasında uygulama parolası | `app.cookieSecure: true`, `app.forwardedAllowIPs` |
| Önde SSO proxy (Keycloak ile oauth2-proxy, Authentik forward auth) | `AUTH_DISABLED=true`, proxy kullanıcı ve grup başlığını iletir, `SSO_ADMIN_GROUPS` (ve `SSO_VIEWER_GROUPS`), ayrıca `TRUSTED_PROXIES` ya da `PROXY_SECRET` |

`AUTH_DISABLED=true` iken NetworkPolicy isteğe bağlı değildir: yoksa cluster içindeki her şey arayüze giriş
yapmadan ulaşır. 0.10'dan beri kullanıcı başlığı taşımayan istekler `401` alır. Çalışan örnekler:
[SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR). `/mcp` uç noktası kendi belirteciyle doğrular ve çoğunlukla
SSO girişinin dışından yönlendirilir.

## Tek replika

Zamanlayıcı sürecin içinde çalışır. İki replika her kontrolü iki kez çalıştırır ve her bildirimi iki kez
gönderir. `replicaCount: 1` kalsın. Arayüzün erişilebilirliği için daha fazla pod gerekiyorsa ek pod'larda
`WDT_SCHEDULER=false` ayarlayın.

## Kubernetes'te denetim izi

Denetim izi `/app/logs` altında bir dosyadır ve varsayılan olarak `emptyDir` üzerindedir. Pod ile birlikte
kaybolur. Saklamanız gereken kayıtlar için ya bir log ajanı ya da sidecar ile gönderin ya da oraya bir
PersistentVolumeClaim bağlayın. `ENVIRONMENT=production` iken yazılamayan log dizini, durum değiştiren
isteklerin denetimsiz ilerlemek yerine `503` ile reddedilmesine yol açar.

## Wazuh ile aynı cluster'da ya da değil

- **Aynı cluster:** servis adlarını kullanın (`https://indexer.wazuh.svc:9200`,
  `https://wazuh.wazuh.svc:55000`). Indexer'ın dışarı açılması gerekmez.
- **Wazuh başka yerde:** pod'ların iç ağınız ya da VPN üzerinden 9200 ve 55000'e yolu ve
  `networkPolicy.wazuhCIDR` gerekir. Bunun için Indexer'ı asla İnternet'e açmayın.
- wazuh-kubernetes'te Indexer kullanıcıları çoğunlukla `internal_users.yml` içinde tanımlıdır; yalnız REST API
  ile oluşturulan kullanıcıyı `securityadmin` silebilir.

## Yükseltme ve geri dönüş

```sh
helm upgrade wazuh-daily-triage wazuh-daily-triage/wazuh-daily-triage \
  --namespace wazuh-daily-triage --version <chart sürümü> -f my-values.yaml
helm -n wazuh-daily-triage rollback wazuh-daily-triage <revizyon>
```

Önce yedek alın ve sürüm notlarını okuyun: [Yükseltme](Upgrade-TR).

*0.11.0, chart 0.3.0 için geçerlidir · gözden geçirme: 2026-11-11*

---

[English](Kubernetes) · [Türkçe](Kubernetes-TR)
