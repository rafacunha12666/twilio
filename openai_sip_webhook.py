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
_LOGGED_WEBHOOK_SECRET_HINTS = False


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
    """Prefer configured caller ID; fallback to the inbound "To" number."""
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


def debug_signature_validation(raw_body: bytes, headers: dict, secrets: list, debug_mode: bool = True) -> None:
    """Debug webhook signature validation by logging hash, preview, and manual verification."""
    import hashlib
    import hmac
    import base64
    
    # Calculate SHA256 hash of body
    body_hash = hashlib.sha256(raw_body).hexdigest()
    print(f"\n=== WEBHOOK DEBUG ===")
    print(f"Body SHA256: {body_hash}")
    print(f"Body length: {len(raw_body)} bytes")
    
    # Log body preview (first 200 chars)
    try:
        body_preview = raw_body[:200].decode('utf-8', errors='replace')
        print(f"Body preview: {body_preview}...")
    except Exception as e:
        print(f"Could not decode body preview: {e}")
    
    # Log all relevant headers
    webhook_id = headers.get("webhook-id", "")
    webhook_timestamp = headers.get("webhook-timestamp", "")
    webhook_signature = headers.get("webhook-signature", "")
    
    print(f"Headers:")
    print(f"  webhook-id: {webhook_id}")
    print(f"  webhook-timestamp: {webhook_timestamp}")
    print(f"  webhook-signature: {webhook_signature[:80]}..." if len(webhook_signature) > 80 else f"  webhook-signature: {webhook_signature}")
    print(f"  User-Agent: {headers.get('User-Agent', 'N/A')}")
    print(f"  Content-Type: {headers.get('Content-Type', 'N/A')}")
    print(f"  Content-Encoding: {headers.get('Content-Encoding', 'N/A')}")
    
    # Manual signature verification for each secret
    print(f"\nManual signature verification ({len(secrets)} secret(s)):")
    for i, secret in enumerate(secrets, 1):
        try:
            # OpenAI webhook signature format: webhook-id.webhook-timestamp.body
            signed_payload = f"{webhook_id}.{webhook_timestamp}.{raw_body.decode('utf-8')}"
            # CRITICAL: OpenAI uses base64, not hexdigest!
            expected_sig = base64.b64encode(
                hmac.new(
                    secret.encode('utf-8'),
                    signed_payload.encode('utf-8'),
                    hashlib.sha256
                ).digest()
            ).decode()
            expected_full = f"v1,{expected_sig}"
            
            # Mask secret for logging
            masked_secret = secret[:10] + "..." + secret[-6:] if len(secret) > 16 else secret[:4] + "..."
            
            matches = hmac.compare_digest(expected_full, webhook_signature)
            print(f"  Secret #{i} ({masked_secret}): {'✓ MATCH' if matches else '✗ NO MATCH'}")
            
            if debug_mode and not matches:
                print(f"    Expected: {expected_full[:80]}...")
                print(f"    Received: {webhook_signature[:80]}...")
                
        except Exception as e:
            print(f"  Secret #{i}: Error during manual verification: {e}")
    
    print(f"=== END DEBUG ===\n")


def unwrap_event(raw_body: bytes, headers: dict) -> dict:
    """
    Validate OpenAI webhook signature using the official helper.
    Supports comma-separated secrets in env (e.g., "whsec_a,whsec_b") to allow
    rolling secrets between local/remoto without downtime.
    """
    from openai import OpenAI

    def _strip_quotes(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and (
            (value.startswith("\"") and value.endswith("\""))
            or (value.startswith("'") and value.endswith("'"))
        ):
            return value[1:-1].strip()
        return value

    raw = os.getenv("OPENAI_WEBHOOK_SECRET", "")
    # Support multiple secrets separated by comma/newline. Also tolerate secrets being
    # pasted with surrounding quotes in env providers.
    raw = raw.replace("\r\n", "\n").replace("\n", ",")
    secrets = [_strip_quotes(s) for s in raw.split(",") if _strip_quotes(s)]
    if not secrets:
        raise SystemExit("Missing OPENAI_WEBHOOK_SECRET in environment.")

    def _mask_secret(secret: str) -> str:
        if len(secret) <= 12:
            return secret[:4] + "…"
        return f"{secret[:10]}…{secret[-6:]}"

    global _LOGGED_WEBHOOK_SECRET_HINTS
    if not _LOGGED_WEBHOOK_SECRET_HINTS:
        masked = ", ".join(_mask_secret(s) for s in secrets)
        print(f"openai webhook secrets loaded ({len(secrets)}): {masked}")
        _LOGGED_WEBHOOK_SECRET_HINTS = True

    # Call debug function before validation attempts
    debug_webhook = os.getenv("DEBUG_WEBHOOK", "false").lower() == "true"
    if debug_webhook:
        debug_signature_validation(raw_body, headers, secrets, debug_webhook)

    last_err: Exception | None = None
    for i, secret in enumerate(secrets, 1):
        try:
            client = OpenAI(api_key=OPENAI_API_KEY, webhook_secret=secret)
            event = client.webhooks.unwrap(raw_body, headers)
            print(f"✓ Signature validated successfully with secret #{i}")
            return event
        except Exception as exc:  # keep trying others
            masked = _mask_secret(secret)
            print(f"✗ Secret #{i} ({masked}) validation failed: {exc}")
            last_err = exc
            continue
    # If none validated, re-raise last error for logging.
    if last_err:
        raise last_err
    raise RuntimeError("No valid webhook secret found.")


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
    import hashlib
    from datetime import datetime
    
    raw_body = request.get_data()
    request_id = request.headers.get('webhook-id', 'unknown')[:16]
    
    try:
        event = unwrap_event(raw_body, request.headers)
    except Exception as exc:
        # Always log body hash for failure analysis
        body_hash = hashlib.sha256(raw_body).hexdigest()
        timestamp = datetime.now().isoformat()
        
        print(f"\n{'='*60}")
        print(f"[{timestamp}] WEBHOOK VALIDATION FAILED (req: {request_id})")
        print(f"Error: {exc}")
        print(f"Body SHA256: {body_hash}")
        print(f"Body length: {len(raw_body)} bytes")
        
        try:
            sig = request.headers.get("webhook-signature", "")
            sig_preview = sig[:48] + ("…" if len(sig) > 48 else "")
            print(
                "Headers:"
                f" id={request.headers.get('webhook-id')}"
                f" ts={request.headers.get('webhook-timestamp')}"
                f" sig={sig_preview}"
                f" ua={request.headers.get('User-Agent')}"
                f" encoding={request.headers.get('Content-Encoding')}"
                f" content_type={request.headers.get('Content-Type')}"
            )
        except Exception:
            pass
        
        # Save body to temp file for offline analysis if debug enabled
        debug_webhook = os.getenv("DEBUG_WEBHOOK", "false").lower() == "true"
        if debug_webhook:
            try:
                debug_file = f"webhook_body_{request_id}_{int(time.time())}.json"
                with open(debug_file, 'wb') as f:
                    f.write(raw_body)
                print(f"Body saved to: {debug_file}")
            except Exception as save_err:
                print(f"Could not save body: {save_err}")
        
        print(f"{'='*60}\n")
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
    return ("", 200)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
