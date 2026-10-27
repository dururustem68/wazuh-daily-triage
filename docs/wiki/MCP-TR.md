# MCP sunucusu

`POST /mcp`, [Model Context Protocol](https://modelcontextprotocol.io) konuşur (Streamable HTTP, JSON yanıtlar).
**Yerleşik yapay zekânın kullandığı salt okunur araştırma araçlarının aynısını** sunar; böylece Claude Desktop
veya başka bir MCP istemcisi, aynı limitlerle Wazuh verilerinizi, raporlarınızı ve bilgi tabanınızı sorgulayabilir.

Uç nokta **varsayılan olarak kapalıdır**. `MCP_TOKEN` yoksa `404` döner.

## Neleri sunar?

| Grup | Araçlar | Gerekli |
|---|---|---|
| Keşif | `list_environments` | her zaman — önce bunu çağırın |
| Alarmlar | `search_alerts`, `aggregate_alerts`, `rule_timeline`, `ip_profile`, `correlate_around` | Indexer |
| Wazuh API | `vulnerabilities`, `agent_info`, `rule_info`, `logtest` | Wazuh API yapılandırılmış olmalı |
| Diğer kaynaklar | `prom_query`, `prom_range`, `loki_query`, `loki_labels`, `k8s_get`, `k8s_logs` | o kaynak yapılandırılmış olmalı |
| Bu uygulama | `list_reports`, `get_report`, `inbox`, `knowledge`, `audit_report` | her zaman |
| Kural taslakları | `validate_rule_xml`, `propose_knowledge` | her zaman |

- **Salt okunur.** Wazuh'u değiştiren, kural dağıtan veya bilgi tabanını düzenleyen araç yoktur.
- `propose_knowledge` yalnızca bir **öneri** ekler; siz arayüzde onaylayana kadar etkisi olmaz.
- `submit_report` (modelin kendi çıktı kanalı) bilinçli olarak sunulmaz.
- Ortamdaki `redact: true` ayarı MCP sonuçlarına da uygulanır.
- `propose_knowledge` dışındaki tüm araçlar `readOnlyHint` taşır.

## Etkinleştirme

1. Uzun ve rastgele bir token üretin:

   ```sh
   openssl rand -hex 32
   ```

2. `MCP_TOKEN` olarak süreç ortamına verin:

   | Kurulum | Nereye |
   |---|---|
   | Docker Compose | `.env` (`APP_PASSWORD`'ın yanına) |
   | Helm | values dosyanızda `secret.MCP_TOKEN` |
   | Kustomize | üretilen Secret (`secret.env`) |
   | Yerel Python | dışa aktarılan kabuk değişkeni |

3. Pod/konteyneri yeniden başlatın. `MCP_TOKEN` her istekte okunur, ancak süreç ortamı açılışta sabitlenir.

4. Test:

   ```sh
   curl -s https://triage.example.com/mcp \
     -H "Authorization: Bearer $MCP_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 400
   ```

`GET /mcp` `405` döner (sunucu tarafından başlatılan akış yok) ve `DELETE /mcp` `204` döner (oturum kapatma).
İstemciler düz istek/yanıt moduna düşer.

## İstemci bağlama

### Claude Desktop (stdio köprüsü)

Claude Desktop yerel MCP sunucularını stdio üzerinden başlatır; depo, stdio'yu `/mcp`'ye ileten standart
kütüphane tabanlı bir köprü içerir: [`tools/mcp_bridge.py`](https://github.com/dururustem68/wazuh-daily-triage/blob/main/tools/mcp_bridge.py).

```sh
printf '%s' "$MCP_TOKEN" > ~/.wdt-mcp-token
chmod 600 ~/.wdt-mcp-token
```

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh-prod": {
      "command": "python3",
      "args": [
        "/path/to/wazuh-daily-triage/tools/mcp_bridge.py",
        "https://triage.example.com/mcp",
        "--token-file", "/home/you/.wdt-mcp-token"
      ]
    }
  }
}
```

- Özel CA: `--ca-file /path/to/ca.pem` ekleyin.
- Yalnızca laboratuvar: `--insecure` TLS doğrulamasını kapatır.
- Windows + WSL: `"command": "wsl.exe"` ve `/mnt/c/...` yolları.
- Token dosya yerine `WDT_MCP_TOKEN` değişkeninden de gelebilir.

### Herhangi bir Streamable HTTP istemcisi

URL'yi `Authorization: Bearer <token>` ve `Content-Type: application/json` ile kullanın.

```sh
# 1. el sıkışma
curl -s https://triage.example.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2025-06-18","capabilities":{},
                 "clientInfo":{"name":"curl","version":"1"}}}'

# 2. bu token'ın kullanabileceği ortamları görün
curl -s https://triage.example.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call",
       "params":{"name":"list_environments","arguments":{}}}'

# 3. sorgu çalıştırın
curl -s https://triage.example.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"search_alerts",
                 "arguments":{"env":"prod","from":"now-24h","min_level":7}}}'
```

Araç sonuçları, JSON içeren tek bir `text` öğesi barındıran `content` dizisi olarak gelir; araç hatalarında
`isError` `true` olur. Desteklenen protokol sürümleri: `2025-06-18`, `2025-03-26`, `2024-11-05`.

## Ortam kapsamı ve limitler

### `MCP_ENVS`

```sh
MCP_ENVS=prod,staging        # boş = yapılandırılmış her ortam
```

- `list_environments` yalnızca izin verilen kimlikleri listeler.
- Her araç bir `env` argümanı alır; şeması izin verilen kimliklerin `enum`'udur.
- Tam olarak bir ortama izin veriliyorsa argüman isteğe bağlıdır; birden çoksa zorunludur.
- Bilinmeyen veya izin verilmeyen bir kimlik hata döner **ve araç çağrısı çalıştırılmaz**.

### Sorgu limitleri

MCP istemcileri de tıpkı model gibi `app/query_guard.py` üzerinden geçer:

```yaml
    query:
      max_range_hours: 336     # çağrı başına 14 gün
      max_buckets: 200
      max_terms_size: 50
      max_size: 25
      min_interval: 1m
      max_concurrent: 8
```

Bilinmeyen alan, tavanı aşan pencere veya ayrıştırılamayan zaman damgası, sorgu Indexer'a ulaşmadan reddedilir.
Bir istemci MCP'yi pahalı bir sorgu motoruna dönüştüremez.

## Proxy arkasında

Uygulama `/mcp` yolunu **herkese açık** sayar çünkü kendi bearer token'ını kendisi kontrol eder; önündeki SSO
vekilinin bu yolu geçirmesi gerekir, aksi halde `Authorization` başlığı uygulamaya ulaşmaz (veya kullanıcı HTML
giriş sayfasına yönlendirilir).

| Vekil | Ayar |
|---|---|
| oauth2-proxy | `--skip-auth-route=POST=^/mcp$` |
| Traefik + Authentik | `Path('/mcp')` için Authentik middleware **olmadan** ikinci bir `IngressRoute` kuralı (gönderilen bileşen bunu yapar) |
| ingress-nginx | `/mcp` için `auth-url` anotasyonları olmayan ayrı bir `Ingress` (anotasyonlar Ingress başına geçerlidir) |

**Ana makineyi iç ağda tutun.** Bu yoldaki tek koruma bearer token'dır; `/mcp`'yi internete açmayın. Token'ı
`MCP_TOKEN` değiştirip yeniden başlatarak döndürün.

## Güvenlik modeli

- **Salt okunur araçlar**, dağıtıcıda zorlanır: MCP modunda `submit_report`, dağıtım ve bilgi tabanı düzenleme
  yoktur. `propose_knowledge` insan onayı bekleyen bir öneri oluşturur.
- **Ortam başına izin listesi** (`MCP_ENVS`) yalnızca şemada değil, araç dağıtıcısında da kontrol edilir.
- **Sorgu koruması** alanları, pencereleri, kovaları ve belge sayılarını sınırlar.
- **Maskeleme** (`redact: true`) istemciye dönen JSON'a uygulanır.
- **Denetim.** `mcp.propose_knowledge` `logs/audit.jsonl` dosyasına yazılır; her araç çağrısı adı ve sonucuyla
  (`mcp search_alerts ok`) INFO seviyesinde loglanır. Argümanlar ve alarm içerikleri denetim kaydına yazılmaz.
- **İstemci enjeksiyonu (prompt injection).** Alarm içeriği saldırgan kontrolündedir; sunucu talimatları
  istemciye bunu veri olarak görmesini söyler. Kandırılan bir model en fazla onaylamanız gereken bir öneri
  ekleyebilir.
- **Kabuk yok, dış istek yok.** Araçlar yalnızca yapılandırılmış Indexer/API/kaynakları sorgular.

## Sorun giderme

| Belirti | Neden ve çözüm |
|---|---|
| `404 {"error":"MCP is disabled (set MCP_TOKEN)"}` | `MCP_TOKEN` boş. Amaçlanan kapalı durumu budur. |
| `401 {"error":"unauthorized"}` | Başlık yok, `Bearer` değil veya token farklı. Vekilden sonra `Authorization` başlığını kontrol edin. |
| `GET` üzerinde `405` | `POST` kullanın; sunucu tarafından başlatılan akış yok. |
| JSON yerine HTML giriş sayfası | SSO vekili `/mcp` yolunu yakaladı; atlama rotası ekleyin. |
| `{ "error": "unknown, missing or not permitted env; one of [...]" }` | `env` argümanı eksik veya `MCP_ENVS` dışında. `list_environments` çağırın. |
| `{ "error": "tool X is not available for Y" }` | Araç Wazuh API'sine veya bu ortamın yapılandırmadığı ek bir kaynağa ihtiyaç duyuyor ya da hariç tutulmuş (`submit_report`). |
| Boş sonuçlar | Pencereyi (`from`/`to`), `min_level` ve ajan/kural filtrelerini kontrol edin. |
| Claude Desktop'ta zaman aşımı | Köprü 180 saniyeye kadar bekler; pencereyi daraltın veya Indexer gecikmesini kontrol edin. |

Sonraki: [Yapılandırma](Configuration-TR) · [Görüntüleyici modu](Viewer-Mode-TR) ·
[SSO proxy kimlik doğrulama](SSO-Proxy-Auth-TR)

---

[English](MCP) · [Türkçe](MCP-TR)
