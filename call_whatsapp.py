import argparse
import os
from typing import Optional

from twilio.rest import Client

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv()  # Carrega variáveis do .env quando python-dotenv está disponível.

def build_twiml(message: str, connect_to: Optional[str]) -> str:
    """Compose a simple TwiML response for the outbound WhatsApp call."""
    if connect_to:
        return (
            "<Response>"
            f"<Say language=\"pt-BR\">{message}</Say>"
            f"<Dial><Number>{connect_to}</Number></Dial>"
            "</Response>"
        )
    return f"<Response><Say language=\"pt-BR\">{message}</Say></Response>"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dispara uma chamada de voz via WhatsApp usando a API de Voice da Twilio."
    )
    parser.add_argument(
        "--to",
        required=True,
        help="Destino WhatsApp no formato E.164 (ex: +5561...). Não inclua o prefixo 'whatsapp:'.",
    )
    parser.add_argument(
        "--from-number",
        default=os.getenv("WHATSAPP_CALL_FROM"),
        help="Número WhatsApp da Twilio habilitado para chamadas de voz (E.164). "
        "Pode vir de WHATSAPP_CALL_FROM.",
    )
    parser.add_argument(
        "--message",
        default="Ola, esta é uma chamada de teste via WhatsApp e Twilio.",
        help="Mensagem falada no início da chamada.",
    )
    parser.add_argument(
        "--twiml-url",
        default=os.getenv("TWILIO_CALL_TWIML_URL"),
        help="URL pública que retorna TwiML (ex.: https://twilio-production-9007.up.railway.app/twilio/voice). "
        "Se informado, substitui o uso do --message.",
    )
    parser.add_argument(
        "--connect-to",
        help="Opcional: número PSTN/SIP/Client para encaminhar após a saudação (E.164 ou client:name).",
    )
    args = parser.parse_args()

    account_sid = os.getenv("TWILIO_SID") or os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_TOKEN") or os.getenv("TWILIO_AUTH_TOKEN")

    if not account_sid or not auth_token:
        parser.error("Defina TWILIO_SID/TWILIO_TOKEN (ou TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN).")
    if not args.from_number:
        parser.error("Informe --from-number ou defina WHATSAPP_CALL_FROM.")

    client = Client(account_sid, auth_token)

    if args.twiml_url:
        call = client.calls.create(
            to=f"whatsapp:{args.to}",
            from_=f"whatsapp:{args.from_number}",
            url=args.twiml_url,
            method="POST",
        )
    else:
        twiml = build_twiml(args.message, args.connect_to)
        call = client.calls.create(
            to=f"whatsapp:{args.to}",
            from_=f"whatsapp:{args.from_number}",
            twiml=twiml,
        )

    print(f"Chamada iniciada. SID: {call.sid}")


if __name__ == "__main__":
    main()
