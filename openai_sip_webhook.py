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
OPENAI_VOICE = os.getenv("OPENAI_REALTIME_VOICE") or os.getenv("VOZ")
SIP_CALLER_ID = (
    os.getenv("TWILIO_SIP_CALLER_ID")
    or os.getenv("WHATSAPP_CALL_FROM")
    or os.getenv("PHONE")
)

OPENAI_GREETING = os.getenv(
    "OPENAI_REALTIME_GREETING",
    "Olá, tudo bem? Eu sou a Paty, consultora da Lemos Leite Advocacia. Qual é o seu nome?",
)
OPENAI_INSTRUCTIONS = os.getenv(
    "OPENAI_REALTIME_INSTRUCTIONS",
    "Voce eh um atendente juridico, somente fale em portugues brasil.",
)
OPENAI_MAX_CALL_SECONDS = float(os.getenv("OPENAI_REALTIME_MAX_CALL_SECONDS", "600"))
END_CALL_TOOL_NAME = "end_call"
OPENAI_FAREWELL_INSTRUCTIONS = os.getenv(
    "OPENAI_REALTIME_FAREWELL",
    "Faca uma despedida curta em portugues e diga que vai encerrar a chamada agora.",
)
END_CALL_PHRASES = (
    "era so isso",
    "era só isso",
    "so isso",
    "só isso",
    "pode desligar",
    "pode encerrar",
    "vou desligar",
    "tchau",
    "ate logo",
    "até logo",
    "nao preciso de mais nada",
    "não preciso de mais nada",
    "nao tenho mais nada",
    "não tenho mais nada",
    "encerrar a chamada",
    "finalizar a chamada",
)

if not OPENAI_API_KEY:
    raise SystemExit("Missing OPENAI_API_KEY in environment.")
if not OPENAI_WEBHOOK_SECRET:
    raise SystemExit("Missing OPENAI_WEBHOOK_SECRET in environment.")

app = Flask(__name__)
AUTH_HEADER = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
_LOGGED_WEBHOOK_SECRET_HINTS = False
_GREETED_CALL_IDS: set[str] = set()
_GREETED_CALL_IDS_LOCK = threading.Lock()


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


def build_call_instructions() -> str:
    return (
        f"{load_instructions().rstrip()}\n\n"
        "=== ENCERRAMENTO DA CHAMADA ===\n"
        "Quando o cliente se despedir, disser que nao precisa de mais nada, "
        "agradecer como encerramento, ou pedir para desligar, chame a ferramenta "
        "end_call. Nao desligue sem antes fazer uma despedida curta."
    )


def extract_greeting_text(raw_greeting: str) -> str:
    """
    Normalize OPENAI_REALTIME_GREETING.

    It’s common to accidentally set the env var to a meta-instruction like:
      "Diga exatamente o seguinte: 'Olá ...'"

    For `response.instructions` we want the literal phrase to be spoken, not the meta-instruction.
    """
    greeting = (raw_greeting or "").strip()
    if not greeting:
        return ""

    lower = greeting.lower().strip()
    if lower.startswith(("diga", "say")):
        import re

        m = re.search(r"['\"](.*?)['\"]", greeting, flags=re.DOTALL)
        if m and m.group(1).strip():
            return m.group(1).strip()

        if ":" in greeting:
            candidate = greeting.split(":", 1)[1].strip().strip("'\"").strip()
            if candidate:
                return candidate

        parts = greeting.split(None, 1)
        if len(parts) == 2:
            candidate = parts[1].strip().strip("'\"").strip()
            if candidate:
                return candidate

    return greeting


def build_greeting_instructions(greeting: str) -> str:
    """
    Build deterministic greeting instructions.

    In Realtime, `response.instructions` is a prompt (not literal output). If we pass a raw greeting
    like "Olá... Qual é o seu nome?", the model may treat it as user input and respond as if it
    were the caller (e.g., "Olá, Paty, eu sou o João"), which looks like "cached" behavior.
    """
    greeting_text = extract_greeting_text(greeting)
    if not greeting_text:
        return ""

    return (
        "Você é a atendente virtual (Paty). Ao atender a chamada, fale APENAS a frase abaixo, "
        "exatamente como está, sem adicionar nada antes ou depois e sem responder como se fosse o cliente:\n"
        f"{greeting_text}"
    )


def should_send_greeting(call_id: str) -> bool:
    with _GREETED_CALL_IDS_LOCK:
        if call_id in _GREETED_CALL_IDS:
            return False
        _GREETED_CALL_IDS.add(call_id)
        return True


def build_end_call_tool() -> dict:
    return {
        "type": "function",
        "name": END_CALL_TOOL_NAME,
        "description": (
            "Call this when the caller clearly wants to end the call, says goodbye, "
            "says there is nothing else needed, or asks to hang up."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Brief reason why the call should end.",
                }
            },
            "required": [],
        },
    }


def build_end_call_session_update() -> dict:
    return {
        "type": "session.update",
        "session": {
            "tools": [build_end_call_tool()],
            "tool_choice": "auto",
        },
    }


def build_farewell_response_create(reason: str) -> dict:
    instructions = (
        f"{OPENAI_FAREWELL_INSTRUCTIONS}\n"
        f"Motivo interno do encerramento: {reason}.\n"
        "Fale apenas a despedida, sem explicar detalhes tecnicos."
    )
    return {
        "type": "response.create",
        "response": {
            "instructions": instructions,
            **({"voice": OPENAI_VOICE} if OPENAI_VOICE else {}),
        },
    }


def build_greeting_response_create(greeting_instructions: str) -> dict:
    return {
        "type": "response.create",
        "response": {
            "instructions": greeting_instructions,
            **({"voice": OPENAI_VOICE} if OPENAI_VOICE else {}),
        },
    }


def is_end_call_tool_event(event: object) -> bool:
    if not isinstance(event, dict):
        return False

    event_type = event.get("type")
    if (
        event_type == "response.function_call_arguments.done"
        and event.get("name") == END_CALL_TOOL_NAME
    ):
        return True

    if event_type != "response.done":
        return False

    response = event.get("response")
    output = response.get("output", []) if isinstance(response, dict) else []
    for item in output:
        if isinstance(item, dict) and item.get("type") == "function_call":
            if item.get("name") == END_CALL_TOOL_NAME:
                return True
    return False


def _normalize_text(value: str) -> str:
    return " ".join(value.lower().strip().split())


def _collect_text_values(value: object) -> list[str]:
    texts: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in ("text", "transcript") and isinstance(child, str):
                texts.append(child)
            else:
                texts.extend(_collect_text_values(child))
    elif isinstance(value, list):
        for child in value:
            texts.extend(_collect_text_values(child))
    return texts


def is_user_end_call_event(event: object) -> bool:
    if not isinstance(event, dict):
        return False

    item = event.get("item")
    if not isinstance(item, dict) or item.get("role") != "user":
        return False

    text = _normalize_text(" ".join(_collect_text_values(item)))
    if not text:
        return False
    return any(phrase in text for phrase in END_CALL_PHRASES)


def debug_signature_validation(raw_body: bytes, headers: dict, secrets: list, debug_mode: bool = True) -> None:
    """Debug webhook signature validation by logging hash, preview, and manual verification."""
    import hashlib
    import hmac
    import base64
    import traceback
    
    # Calculate SHA256 hash of body
    body_hash = hashlib.sha256(raw_body).hexdigest()
    print(f"\n=== WEBHOOK DEBUG ===")
    print(f"Body SHA256: {body_hash}")
    print(f"Body length: {len(raw_body)} bytes")
    print(f"Body HEX (first 64 bytes): {raw_body[:64].hex()}")
    
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
    
    # Prepare body variations to test against modification issues
    variations = {
        "RAW": raw_body,
        "STRIPPED": raw_body.strip(),
        "TO_LF": raw_body.replace(b'\r\n', b'\n'),
        "TO_CRLF": raw_body.replace(b'\n', b'\r\n').replace(b'\r\r\n', b'\r\n'),
        "UTF8_NORM": raw_body.decode('utf-8', 'replace').encode('utf-8')
    }

    for i, secret in enumerate(secrets, 1):
        try:
            masked_secret = secret[:10] + "..." + secret[-6:] if len(secret) > 16 else secret[:4] + "..."
            match_found = False
            
            for var_name, body_var in variations.items():
                # OpenAI webhook signature format: webhook-id.webhook-timestamp.body
                signed_payload = f"{webhook_id}.{webhook_timestamp}.".encode('utf-8') + body_var
                
                # CRITICAL: OpenAI uses base64, not hexdigest!
                expected_sig = base64.b64encode(
                    hmac.new(
                        secret.encode('utf-8'),
                        signed_payload,
                        hashlib.sha256
                    ).digest()
                ).decode()
                expected_full = f"v1,{expected_sig}"
                
                matches = hmac.compare_digest(expected_full, webhook_signature)
                
                if matches:
                    print(f"  Secret #{i} ({masked_secret}): ✓ MATCH with {var_name}")
                    match_found = True
                    break
                elif var_name == "RAW":
                    # Only log failure details for RAW to avoid noise
                    print(f"  Secret #{i} ({masked_secret}): ✗ NO MATCH (Raw)")
                    if debug_mode:
                        print(f"    Expected: {expected_full[:80]}...")
                        print(f"    Received: {webhook_signature[:80]}...")
            
            if not match_found and debug_mode:
                 print(f"    (Tried variations: {', '.join(variations.keys())} - none matched)")

        except Exception as e:
            print(f"  Secret #{i}: Error during manual verification: {e}")
            traceback.print_exc()
    
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
        "instructions": build_call_instructions(),
        "tools": [build_end_call_tool()],
        "tool_choice": "auto",
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


def hangup_call(call_id: str) -> requests.Response | None:
    """End an active OpenAI Realtime SIP call."""
    url = f"https://api.openai.com/v1/realtime/calls/{call_id}/hangup"
    for attempt in range(1, 4):
        try:
            resp = requests.post(
                url,
                headers=AUTH_HEADER,
                timeout=(3.05, 20),
            )
            return resp
        except requests.RequestException as exc:
            print(f"hangup attempt {attempt} failed: {exc}")
            time.sleep(0.5 * attempt)
    return None


def _parse_realtime_event(raw: object) -> dict | None:
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return json.loads(raw) if isinstance(raw, str) else raw
    except Exception as exc:
        preview = raw[:200] if isinstance(raw, str) else str(raw)[:200]
        print(f"[monitor] event parse error {exc} preview={preview!r}", flush=True)
        return None


async def _wait_for_event_type(
    websocket,
    call_id: str,
    wanted_types: tuple[str, ...],
    timeout: float = 2.0,
) -> dict | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=0.5)
        except asyncio.TimeoutError:
            continue
        except Exception as exc:
            print(f"[monitor] wait recv error (call_id={call_id}): {exc}", flush=True)
            return None

        event = _parse_realtime_event(raw)
        event_type = event.get("type") if isinstance(event, dict) else None
        print(f"[monitor] wait event={event_type} (call_id={call_id})", flush=True)
        if event_type == "error":
            print(f"[monitor] error payload={event} (call_id={call_id})", flush=True)
        if event_type in wanted_types:
            return event
    print(f"[monitor] wait timed out for {wanted_types} (call_id={call_id})", flush=True)
    return None


async def _wait_for_audio_drained(websocket, call_id: str, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=0.75)
        except asyncio.TimeoutError:
            continue
        except Exception as exc:
            print(f"[monitor] audio-drain recv error (call_id={call_id}): {exc}", flush=True)
            return

        event = _parse_realtime_event(raw)
        event_type = event.get("type") if isinstance(event, dict) else None
        print(f"[monitor] drain event={event_type} (call_id={call_id})", flush=True)
        if event_type == "output_audio_buffer.stopped":
            return


async def _send_farewell_and_hangup(websocket, call_id: str, reason: str) -> None:
    await websocket.send(json.dumps(build_farewell_response_create(reason), ensure_ascii=False))
    print(f"[monitor] farewell requested reason={reason} (call_id={call_id})", flush=True)
    await _wait_for_audio_drained(websocket, call_id)
    resp = hangup_call(call_id)
    if resp is None:
        print(f"[monitor] hangup failed after retries (call_id={call_id})", flush=True)
    elif not resp.ok:
        print(f"[monitor] hangup failed {resp.status_code}: {resp.text}", flush=True)
    else:
        print(f"[monitor] hangup ok {resp.status_code} (call_id={call_id})", flush=True)


async def _send_initial_realtime_events(websocket, call_id: str) -> None:
    await _wait_for_event_type(websocket, call_id, ("session.created",), timeout=2.0)
    await websocket.send(json.dumps(build_end_call_session_update(), ensure_ascii=False))
    print(f"[monitor] end-call tool update sent (call_id={call_id})", flush=True)
    await _wait_for_event_type(websocket, call_id, ("session.updated",), timeout=2.0)

    if OPENAI_GREETING and should_send_greeting(call_id):
        greeting_instructions = build_greeting_instructions(OPENAI_GREETING)
        if greeting_instructions:
            response_create = build_greeting_response_create(greeting_instructions)
            await websocket.send(json.dumps(response_create, ensure_ascii=False))
            print(f"[monitor] greeting requested (call_id={call_id})", flush=True)


async def _monitor_connected_websocket(websocket, call_id: str) -> None:
    await _send_initial_realtime_events(websocket, call_id)
    deadline = time.monotonic() + OPENAI_MAX_CALL_SECONDS

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            await _send_farewell_and_hangup(websocket, call_id, "max_call_seconds")
            return

        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=min(1.0, remaining))
        except asyncio.TimeoutError:
            continue
        except Exception as exc:
            print(f"[monitor] websocket recv error (call_id={call_id}): {exc}", flush=True)
            return

        event = _parse_realtime_event(raw)
        event_type = event.get("type") if isinstance(event, dict) else None
        print(f"[monitor] event={event_type} (call_id={call_id})", flush=True)
        if event_type == "error":
            print(f"[monitor] error payload={event} (call_id={call_id})", flush=True)
        if is_end_call_tool_event(event):
            await _send_farewell_and_hangup(websocket, call_id, "agent_end_call")
            return
        if is_user_end_call_event(event):
            await _send_farewell_and_hangup(websocket, call_id, "user_end_call")
            return


async def monitor_realtime_call(call_id: str) -> None:
    try:
        import websockets
    except ImportError:
        print(f"[monitor] websockets not installed; monitor skipped (call_id={call_id})")
        return

    ws_url = f"wss://api.openai.com/v1/realtime?call_id={call_id}"
    print(f"[monitor] connecting websocket (call_id={call_id})", flush=True)
    try:
        try:
            async with websockets.connect(ws_url, extra_headers=AUTH_HEADER) as websocket:
                await _monitor_connected_websocket(websocket, call_id)
        except TypeError:
            async with websockets.connect(ws_url, additional_headers=AUTH_HEADER) as websocket:
                await _monitor_connected_websocket(websocket, call_id)
    except Exception as exc:
        print(f"[monitor] websocket error (call_id={call_id}): {exc}", flush=True)


def start_call_monitor_thread(call_id: str) -> None:
    print(f"[monitor] starting monitor thread (call_id={call_id})", flush=True)
    threading.Thread(
        target=lambda: asyncio.run(monitor_realtime_call(call_id)),
        daemon=True,
    ).start()


async def send_greeting(call_id: str) -> None:
    try:
        import websockets
    except ImportError:
        print(
            f"[greeting] websockets not installed; greeting skipped (call_id={call_id})",
            flush=True,
        )
        return

    greeting_instructions = build_greeting_instructions(OPENAI_GREETING)
    if not greeting_instructions:
        print(
            f"[greeting] no greeting text configured; skipping (call_id={call_id})",
            flush=True,
        )
        return

    print(
        f"[greeting] built instructions: {greeting_instructions!r} (call_id={call_id})",
        flush=True,
    )

    response_create = {
        "type": "response.create",
        "response": {
            "instructions": greeting_instructions,
            **({"voice": OPENAI_VOICE} if OPENAI_VOICE else {}),
        },
    }

    async def _recv_event(websocket, label: str, timeout: float = 1.0) -> None:
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            print(
                f"[greeting] {label}: no event within {timeout:.1f}s (call_id={call_id})",
                flush=True,
            )
            return
        except Exception as exc:
            print(
                f"[greeting] {label}: recv error {exc} (call_id={call_id})",
                flush=True,
            )
            return

        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            if isinstance(raw, str):
                preview = raw[:400]
                print(
                    f"[greeting] {label}: raw preview={preview!r} (call_id={call_id})",
                    flush=True,
                )
            event = json.loads(raw) if isinstance(raw, str) else raw
            event_type = event.get("type") if isinstance(event, dict) else None
            print(
                f"[greeting] {label}: received {event_type or type(event)} (call_id={call_id})",
                flush=True,
            )
            if isinstance(event, dict) and event.get("type") in ("error", "response.error"):
                print(
                    f"[greeting] {label}: error payload={event} (call_id={call_id})",
                    flush=True,
                )
        except Exception as exc:
            preview = raw[:200] if isinstance(raw, str) else str(raw)[:200]
            print(
                f"[greeting] {label}: parse error {exc} preview={preview!r} (call_id={call_id})",
                flush=True,
            )

    ws_url = f"wss://api.openai.com/v1/realtime?call_id={call_id}"
    print(
        f"[greeting] connecting websocket for call_id={call_id} voice={OPENAI_VOICE or 'default'}",
        flush=True,
    )

    # Try a couple of times in case the session is not fully ready yet
    for attempt in range(1, 3):
        try:
            async with websockets.connect(ws_url, extra_headers=AUTH_HEADER) as websocket:
                await _recv_event(websocket, "session", timeout=0.5)
                await asyncio.sleep(0.35 * attempt)
                await websocket.send(json.dumps(response_create, ensure_ascii=False))
                print(
                    f"[greeting] sent response.create (call_id={call_id}, attempt={attempt})",
                    flush=True,
                )
                await _recv_event(websocket, "response", timeout=0.5)
                return
        except TypeError:
            async with websockets.connect(ws_url, additional_headers=AUTH_HEADER) as websocket:
                await _recv_event(websocket, "session", timeout=0.5)
                await asyncio.sleep(0.35 * attempt)
                await websocket.send(json.dumps(response_create, ensure_ascii=False))
                print(
                    f"[greeting] sent response.create (call_id={call_id}, attempt={attempt})",
                    flush=True,
                )
                await _recv_event(websocket, "response", timeout=0.5)
                return
        except Exception as exc:
            print(
                f"[greeting] websocket error (call_id={call_id}, attempt={attempt}): {exc}",
                flush=True,
            )
            await asyncio.sleep(0.3)


def start_greeting_thread(call_id: str) -> None:
    print(f"[greeting] starting greeting thread (call_id={call_id})", flush=True)
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
        
        # Check if we should skip validation (EMERGENCY MODE)
        skip_validation = os.getenv("SKIP_WEBHOOK_VALIDATION", "false").lower() == "true"
        
        try:
            sig = request.headers.get("webhook-signature", "")
            sig_preview = sig[:48] + ("…" if len(sig) > 48 else "")
            print(
                "Headers:"
                f" id={request.headers.get('webhook-id')}"
                f" ts={request.headers.get('webhook-timestamp')}"
                f" sig={sig_preview}"
            )
        except Exception:
            pass
        
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
        
        if skip_validation:
            print("!!! WARNING: SKIP_WEBHOOK_VALIDATION is enabled. Proceeding despite validation failure. !!!")
            try:
                event = json.loads(raw_body)
            except Exception as json_err:
                 print(f"CRITICAL: Failed to parse raw JSON body: {json_err}")
                 return ("", 400)
        else:
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
                start_call_monitor_thread(call_id)

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
        "statusCallbackMethod=\"POST\" "
        "record=\"record-from-answer-dual\" "
        "recordingStatusCallback=\"https://n8n-production-fcb8b.up.railway.app/webhook/twilio_recording\" "
        "recordingStatusCallbackEvent=\"completed\""
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
    return Response(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response></Response>",
        mimetype="text/xml",
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
