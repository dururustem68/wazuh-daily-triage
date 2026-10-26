# Yapay zekâ sağlayıcıları

Wazuh Daily Triage iki API türüyle konuşur: **Anthropic Messages** (`LLM_PROVIDER=anthropic`) ve
**OpenAI Chat Completions** (`LLM_PROVIDER=openai`, uyumlu her uç nokta). Model **araç kullanımını (tool /
function calling)** desteklemelidir; ajan incelemesini araçlarla yürütür.

Model adları sık değişir. Aşağıdakiler Ekim 2026'da sağlayıcıların dokümanlarından alındı; güncel liste için
bağlantılı sayfaya bakın.

Ayarlar `.env`'de (tek ortam) ya da `config/environments.yaml`'ın `llm:` bloğunda (genel veya ortam başına)
verilebilir. Değişken listesi için [providers.md](providers.md) başındaki tabloya bakın
(`LLM_TEMPERATURE`, `LLM_TOKEN_PARAM`, `LLM_REASONING_EFFORT`, `LLM_EXTRA_BODY`, `LLM_MAX_TOOL_STEPS`).

Değişiklikten sonra `docker compose exec triage python -m app.check` çalıştırın; son satır modeli dener.

## Claude (Anthropic)

Anahtar: <https://console.anthropic.com/> · Modeller: <https://platform.claude.com/docs/en/models/overview>

```sh
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-5-5
LLM_API_KEY=sk-ant-...
```

- Dokümandaki modeller: `claude-sonnet-5-5` (hız/zekâ dengesi — iyi bir varsayılan), `claude-opus-5-5` (en
  yetenekli), `claude-haiku-5-5` (hızlı, düşük maliyet).
- Sistem istemi önbelleğe alınır (prompt caching); bir koşudaki ardışık araç adımları daha ucuza gelir.

## OpenAI

Anahtar: <https://platform.openai.com/api-keys> · Modeller: <https://developers.openai.com/api/docs/models>

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-6.1-sol
LLM_API_KEY=sk-...
LLM_TOKEN_PARAM=max_completion_tokens
LLM_TEMPERATURE=none
LLM_REASONING_EFFORT=medium
```

- Dokümandaki modeller: `gpt-6-astra` (amiral gemisi), `gpt-6.1-sol` (daha düşük maliyetle ona yakın — iyi bir
  varsayılan), `gpt-6-luna` (küçük, yüksek hacim).
- OpenAI akıl yürütme modelleri `max_tokens` yerine `max_completion_tokens` bekler ve özel `temperature`'ı
  genellikle reddeder; yukarıdaki iki ayar bunu çözer. Bu parametrelerden birini anan bir `400` hatası alırsanız
  çözüm budur.
- **Azure OpenAI:** `LLM_BASE_URL`'e tam deployment adresini yazın
  (`https://<kaynak>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<sürüm>`).

## Google Gemini

Anahtar: <https://aistudio.google.com/apikey> · Doküman: <https://ai.google.dev/gemini-api/docs/openai>

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_MODEL=gemini-3.8-flash
LLM_API_KEY=AIza...
# isteğe bağlı: LLM_REASONING_EFFORT=low|medium|high
```

- Gemini'nin OpenAI uyumlu uç noktası kullanılır; araç kullanımı desteklenir. Google bu katmanı **beta**
  olarak işaretliyor.
- `gemini-3.8-flash` Google'ın örneklerindeki model; zor ortamlar için AI Studio'dan daha büyük birini seçin.
- `reasoning_effort` Gemini'nin düşünme seviyelerine eşlenir; `LLM_EXTRA_BODY` içinde `thinking_config` ile
  birlikte kullanmayın.

## DeepSeek

Anahtar: <https://platform.deepseek.com/api_keys> · Doküman: <https://api-docs.deepseek.com/>

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL=deepseek-flash
LLM_API_KEY=sk-...
```

- Dokümandaki modeller: `deepseek-flash` (hızlı, düşük maliyet) ve `deepseek-v4-pro` (daha güçlü).
- Düşünme modu: `LLM_EXTRA_BODY={"thinking": {"type": "enabled"}}` ve `LLM_REASONING_EFFORT=high`.
- DeepSeek ayrıca Anthropic uyumlu bir uç nokta sunar (`LLM_PROVIDER=anthropic`,
  `LLM_BASE_URL=https://api.deepseek.com/anthropic`); test edilen yol yukarıdaki OpenAI uyumlu olandır.
- **Verinin konumu:** barındırılan DeepSeek API'si Çin'den işletilir. Alarm verinizin nereye gidebileceğini
  (KVKK, GDPR, BDDK gibi sektör kuralları) değerlendirin; açık ağırlıklı DeepSeek modelleri Ollama/vLLM ile yerelde
  de çalıştırılabilir.

## Yerel modeller (Ollama, vLLM, LM Studio)

```sh
docker compose --profile ollama up -d
docker exec -it ollama ollama pull qwen3:14b
```

```sh
LLM_PROVIDER=openai
LLM_BASE_URL=http://ollama:11434/v1
LLM_MODEL=qwen3:14b
LLM_API_KEY=
```

Alarm verisi ağınızdan çıkmaz. Araç kullanımı güvenilir bir model seçin; küçük modeller erken durabilir ya da
`submit_report`'u atlayabilir.

## Ortam başına farklı model

```yaml
llm:                       # tüm ortamlar için varsayılan
  provider: anthropic
  model: claude-sonnet-5-5
  api_key: ${LLM_API_KEY}

environments:
  - id: duzenlemeli
    # ...
    llm:                   # bu ortamın verisi hiçbir zaman barındırılan bir modele gitmez
      provider: openai
      base_url: http://ollama:11434/v1
      model: qwen3:14b
```
