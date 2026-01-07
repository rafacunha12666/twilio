import os
import json
import time
import threading
import traceback
import asyncio
from pathlib import Path
import requests
from flask import Flask, request, Response

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except Exception:
    pass


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_WEBHOOK_SECRET = os.getenv("OPENAI_WEBHOOK_SECRET")
OPENAI_MODEL = os.getenv("OPENAI_REALTIME_MODEL", "gpt-realtime")
OPENAI_PROJECT_ID = os.getenv("OPENAI_PROJECT_ID", "proj_rdAK2E2QH1eN1JRxhquKJssT")
OPENAI_SIP_REGION = os.getenv("OPENAI_SIP_REGION", "br1")
OPENAI_PROMPT_PATH = os.getenv(
    "OPENAI_PROMPT_PATH",
    str(Path(__file__).with_name("prompt-paty.txt")),
)
SIP_CALLER_ID = (
    os.getenv("TWILIO_SIP_CALLER_ID")
    or os.getenv("WHATSAPP_CALL_FROM")
    or os.getenv("PHONE")
)

OPENAI_GREETING = os.getenv("OPENAI_REALTIME_GREETING", "Diga extamente o seguinte: 'Olá , tudo bem? Eu sou a Paty, consultora da Lemos Leite Advocacia.Qual é o seu nome?'")
OPENAI_INSTRUCTIONS = os.getenv(
    "OPENAI_REALTIME_INSTRUCTIONS",
    "Voce eh um atendente juridico, somente fale em portugues brasil.",
)

if not OPENAI_API_KEY:
    raise SystemExit("Missing OPENAI_API_KEY in environment.")
if not OPENAI_WEBHOOK_SECRET:
    raise SystemExit("Missing OPENAI_WEBHOOK_SECRET in environment.")

app = Flask(__name__)
AUTH_HEADER = {"Authorization": f"Bearer {OPENAI_API_KEY}"}


def build_sip_uri() -> str:
    region = OPENAI_SIP_REGION.strip()
    if region:
        return f"sip:{OPENAI_PROJECT_ID}@sip.api.openai.com;transport=tls;region={region}"
    return f"sip:{OPENAI_PROJECT_ID}@sip.api.openai.com;transport=tls"

def normalize_e164(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if value.lower().startswith("whatsapp:"):
        value = value.split(":", 1)[1]
    digits = "".join(ch for ch in value if ch.isdigit())
    if not digits:
        return None
    normalized = f"+{digits}"
    if len(digits) < 8:
        return None
    return normalized


def pick_caller_id(req_form: dict) -> str | None:
    """Prefer inbound caller (converted to E.164), fallback to configured caller ID, then To/Called."""
    inbound_from = req_form.get("From") or req_form.get("Caller")
    normalized_inbound = normalize_e164(inbound_from)
    if normalized_inbound:
        return normalized_inbound

    caller_id = normalize_e164(SIP_CALLER_ID)
    if caller_id:
        return caller_id

    for key in ("To", "Called"):
        candidate = normalize_e164(req_form.get(key))
        if candidate:
            return candidate
    return None


def load_instructions() -> str:
    if OPENAI_PROMPT_PATH:
        try:
            return Path(OPENAI_PROMPT_PATH).read_text(encoding="utf-8")
        except Exception as exc:
            print(f"failed to load prompt file '{OPENAI_PROMPT_PATH}': {exc}")
    return OPENAI_INSTRUCTIONS


def unwrap_event(raw_body: bytes, headers: dict) -> dict:
    """Validate OpenAI webhook signature using the official helper."""
    from openai import OpenAI

    client = OpenAI(api_key=OPENAI_API_KEY, webhook_secret=OPENAI_WEBHOOK_SECRET)
    return client.webhooks.unwrap(raw_body, headers)


def accept_call(call_id: str) -> requests.Response | None:
    """Send accept to OpenAI Realtime SIP call with retries."""
    url = f"https://api.openai.com/v1/realtime/calls/{call_id}/accept"
    body = {
        "type": "realtime",
        "model": OPENAI_MODEL,
        "instructions": load_instructions(),
    }
    for attempt in range(1, 4):
        try:
            resp = requests.post(
                url,
                headers={**AUTH_HEADER, "Content-Type": "application/json"},
                data=json.dumps(body),
                timeout=(3.05, 20),
            )
            return resp
        except requests.RequestException as exc:
            print(f"accept attempt {attempt} failed: {exc}")
            time.sleep(0.5 * attempt)
    return None


async def send_greeting(call_id: str) -> None:
    try:
        import websockets
    except ImportError:
        print("websockets not installed; greeting skipped.")
        return

    response_create = {
        "type": "response.create",
        "response": {
            "instructions": OPENAI_GREETING,
        },
    }

    ws_url = f"wss://api.openai.com/v1/realtime?call_id={call_id}"
    try:
        async with websockets.connect(ws_url, extra_headers=AUTH_HEADER) as websocket:
            await websocket.send(json.dumps(response_create))
    except TypeError:
        async with websockets.connect(ws_url, additional_headers=AUTH_HEADER) as websocket:
            await websocket.send(json.dumps(response_create))
    except Exception as exc:
        print(f"websocket error: {exc}")


def start_greeting_thread(call_id: str) -> None:
    threading.Thread(
        target=lambda: asyncio.run(send_greeting(call_id)),
        daemon=True,
    ).start()


@app.post("/openai/webhook")
def handle_webhook():
    raw_body = request.get_data()
    try:
        event = unwrap_event(raw_body, request.headers)
    except Exception as exc:
        print(f"signature validation failed: {exc}")
        traceback.print_exc()
        # Return 200 to avoid retries storm; log and inspect.
        return ("", 200)

    event_type = getattr(event, "type", None)
    if event_type is None and isinstance(event, dict):
        event_type = event.get("type")

    if event_type == "realtime.call.incoming":
        if isinstance(event, dict):
            call_id = event["data"]["call_id"]
        else:
            call_id = event.data.call_id
        print(f"openai incoming call: {call_id}")
        def _accept_worker() -> None:
            resp = accept_call(call_id)
            if resp is None:
                print("accept failed after retries")
                return
            if not resp.ok:
                print(f"accept failed {resp.status_code}: {resp.text}")
            else:
                print(f"accept ok {resp.status_code}")
                if OPENAI_GREETING:
                    start_greeting_thread(call_id)

        threading.Thread(target=_accept_worker, daemon=True).start()
    else:
        print(f"Unhandled event: {event_type}")

    return ("", 200)


@app.post("/twilio/voice")
def twilio_voice():
    sip_uri = build_sip_uri()
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    base = f"{proto}://{host}"
    status_url = f"{base}/twilio/dial-status"
    action_url = f"{base}/twilio/dial-action"
    caller_id = pick_caller_id(request.form)
    if SIP_CALLER_ID and not normalize_e164(SIP_CALLER_ID):
        print(f"invalid SIP_CALLER_ID: {SIP_CALLER_ID}")
    print(f"using callerId: {caller_id}")
    twiml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<Response>"
        f"<Dial action=\"{action_url}\" method=\"POST\" "
        f"statusCallback=\"{status_url}\" "
        "statusCallbackEvent=\"initiated ringing answered completed\" "
        "statusCallbackMethod=\"POST\""
        + (f" callerId=\"{caller_id}\"" if caller_id else "")
        + ">"
        f"<Sip>{sip_uri}</Sip>"
        "</Dial>"
        "</Response>"
    )
    return Response(twiml, mimetype="text/xml")


@app.post("/twilio/dial-status")
def twilio_dial_status():
    payload = {k: v for k, v in request.form.items()}
    print(f"twilio dial status: {payload}")
    return ("", 200)


@app.post("/twilio/dial-action")
def twilio_dial_action():
    payload = {k: v for k, v in request.form.items()}
    print(f"twilio dial action: {payload}")
    return Response("<Response/>", mimetype="text/xml")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
