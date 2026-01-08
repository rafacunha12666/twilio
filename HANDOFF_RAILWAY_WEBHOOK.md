# Handoff: Twilio WhatsApp Voice → OpenAI Realtime SIP (Railway)

Este documento resume o fluxo, os sintomas, as tentativas de correção e os commits relevantes para investigação do problema **“assinatura do webhook do OpenAI não valida no Railway”**, causando falha no leg SIP e erro Twilio `13224`.

## Fluxo esperado

1. **WhatsApp inbound/outbound (Twilio Voice)** chega no **TwiML App**.
2. Twilio chama o webhook do app (`POST /twilio/voice`) e recebe TwiML com:
   - `<Dial callerId="+E164">`
   - `<Sip>sip:proj_...@sip.api.openai.com;transport=tls;region=...</Sip>`
3. Twilio abre um **leg SIP** para `sip.api.openai.com`.
4. OpenAI dispara webhook **`realtime.call.incoming`** para `POST /openai/webhook` (com headers `webhook-id`, `webhook-timestamp`, `webhook-signature`).
5. Nosso servidor valida assinatura, extrai `call_id` e chama:
   - `POST https://api.openai.com/v1/realtime/calls/{call_id}/accept`
6. Se aceito, o SIP leg completa (`DialSipResponseCode=200`, `DialBridged=true`).

## Sintoma no Railway (falha)

- O webhook **chega** no Railway com `User-Agent: OpenAI/1.0`, mas a validação falha:
  - `openai.InvalidWebhookSignatureError: The given webhook signature does not match the expected signature`
- Como o call não é aceito, o SIP leg falha:
  - `DialSipResponseCode=400`
  - Twilio reporta `ErrorCode=13224` / `ErrorMessage=invalid phone number format`

Exemplo de log no Railway (já com log de headers):

```
openai webhook secrets loaded (1): whsec_16sl…076DY=
signature validation failed: The given webhook signature does not match the expected signature
webhook headers: id=wh_... ts=... sig=v1,... ua=OpenAI/1.0 ... content_type=application/json body_len=1680
```

## Cenário que funciona (local + ngrok)

Rodando local (`python openai_sip_webhook.py`) exposto via ngrok:

- `openai incoming call: rtc_u1_...`
- `accept ok 200`
- Twilio dial-action:
  - `DialSipResponseCode=200`
  - `DialBridged=true`

Isso confirma que o fluxo e o código funcionam quando a validação do webhook passa.

## Variáveis de ambiente relevantes

### No servidor (Railway/local)

- `OPENAI_API_KEY`
- `OPENAI_WEBHOOK_SECRET` (secret do webhook do OpenAI; **não** confundir com API key)
- `OPENAI_PROJECT_ID` (ex: `proj_...`) — usado no SIP URI
- `OPENAI_SIP_REGION` (ex: `br1`)
- `OPENAI_REALTIME_MODEL` (ex: `gpt-realtime`)
- `OPENAI_REALTIME_GREETING` (opcional)
- `TWILIO_SIP_CALLER_ID` (E.164, ex `+5561...`)

Observações:
- No Railway, evitar aspas em env (`KEY=value`), mas o código agora tolera aspas.
- `TWILIO_CALL_TWIML_URL` **não é necessário** para o servidor; é usado apenas pelo `call_whatsapp.py`.

## Investigação já feita / tentativas

### 1) Erro Twilio `13224` em SIP leg

Quando o `<Dial>` não tinha `callerId`, o leg SIP frequentemente saía com `From=whatsapp:+...` e o OpenAI respondia `400`, que a Twilio reportava como `13224`.

Correção aplicada: incluir `callerId` no `<Dial>` com número E.164 (ex: `+556136863636`), e normalizar entradas.

### 2) “Funciona só quando o servidor local está ligado”

Sintoma observado antes: chamadas via Railway pareciam funcionar só quando o local estava ligado. Isso foi explicado por:

- Existirem webhooks diferentes (local vs remoto) ou secrets diferentes.
- O endpoint que conseguia validar assinatura aceitava o `call_id`; o outro recebia `call_id_not_found` ou falhava validação.

### 3) Signature mismatch no Railway (causa atual)

Mesmo após:
- deletar/recriar webhook no OpenAI para o endpoint do Railway
- atualizar `OPENAI_WEBHOOK_SECRET`
- adicionar suporte a múltiplos secrets + strip de aspas
- logar headers do webhook
- pin da versão do SDK `openai`

…a validação ainda falha no Railway.

## Commits relevantes (comportamentos)

Ordem (mais recente primeiro):

- `7e3c535` — **Pin** `openai==1.107.2` em `requirements.txt` para tentar igualar o local.
- `61fa29c` — Logs extras no Railway: secrets mascarados + headers do webhook em caso de falha.
- `616a800` — Tolerância a **aspas** e múltiplos secrets em `OPENAI_WEBHOOK_SECRET`.
- `16385c3` — Suporte a **múltiplos** secrets (lista separada por vírgula).
- `bda689b` — “Modo local funcionando” (estado que funcionou local/geral).
- `ed250ea` / `96b834a` — Ajustes de `callerId`/normalização para evitar `13224`.

## Hipóteses em aberto (para o programador)

1) **Secret realmente divergente do webhook ativo**
   - Mesmo com logs do secret carregado, pode existir diferença sutil (caractere invisível, copy/paste incorreto, secret de outro project).
   - Confirmar no OpenAI Console que o webhook foi criado **no mesmo Project ID** usado no SIP (`proj_rdAK...`).

2) **Payload do webhook chegando alterado no Railway**
   - A assinatura é sobre `webhook-id.webhook-timestamp.body`.
   - Se o body chega com qualquer alteração (ex.: normalização de Unicode, reserialização, whitespace), a assinatura quebra.
   - Próxima ação recomendada: logar hash do body (SHA256) e, se necessário, salvar body bruto para comparação com ambiente local (sem expor dados em log público).

3) **Incompatibilidade de validação do SDK vs especificação**
   - Menos provável, pois local valida, e foi feito pin do SDK.
   - Ainda assim, comparar manualmente a assinatura com um script standalone (HMAC) usando os valores logados.

## Como reproduzir rapidamente

1) Inbound (Twilio):
   - Twilio Voice URL: `https://twilio-production-9007.up.railway.app/twilio/voice`
2) Webhook OpenAI:
   - URL: `https://twilio-production-9007.up.railway.app/openai/webhook`
3) Fazer uma ligação inbound para o WhatsApp sender, e observar:
   - No Railway: logs `openai incoming call` + `accept ok 200` **(quando funciona)**
   - No Twilio: child call SIP `Completed` e `DialSipResponseCode=200`

