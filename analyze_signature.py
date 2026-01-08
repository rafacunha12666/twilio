#!/usr/bin/env python3
"""
Analyze the signature mismatch from Railway logs
"""
import hashlib
import hmac
import json

# From Railway logs:
webhook_id = "wh_695f086f6e208190aefdc28ae0d036e9"
webhook_timestamp = "1767835759"
webhook_signature_received = "v1,nRB08z9NpRP75UacZWwNrsdjza5lxfxThZ67XhP8Ulo="
body_sha256 = "b9808d9c50906a07b489b0d22166f77ad73f653caeff85ab1bdeeaf2c6afd547"
body_preview = '{"id": "evt_695f086f62008190a17068a75fc156c3", "object": "event", "created_at": 1767835759, "type": "realtime.call.incoming", "data": {"call_id": "rtc_u2_f5b52310bec846f083219e508d3fc205", "sip_header'

# Our calculated signature from logs:
our_calculated = "v1,cfa26684e4b784a4be334fcee4e198775685bc4354b1747486e743f415481b20"

print("=" * 70)
print("SIGNATURE ANALYSIS")
print("=" * 70)

print(f"\nReceived from OpenAI:")
print(f"  webhook-signature: {webhook_signature_received}")

print(f"\nCalculated by our code:")
print(f"  Expected: {our_calculated}")

print(f"\n❌ Signatures DO NOT MATCH")

print(f"\n" + "=" * 70)
print("POSSIBLE CAUSES")
print("=" * 70)

print("""
The signature is calculated as:
  HMAC-SHA256(webhook-id.webhook-timestamp.body, secret)

Since the secret is correct (works locally), the issue MUST be:

1. ⚠️  The 'body' we're reading is different from what OpenAI signed

Possible reasons:

A) Flask/Gunicorn is modifying the body:
   - Adding/removing whitespace
   - Changing encoding
   - Normalizing line endings
   - Adding BOM (Byte Order Mark)

B) Railway's proxy is modifying the request:
   - Decompressing/recompressing
   - Charset conversion
   - Header manipulation affecting body read

C) Flask request.get_data() is not reading raw bytes correctly:
   - Cache issue
   - Stream already consumed
   - WSGI environment differences

SOLUTION:
==========

Instead of relying on Flask to process headers into a dict,
we need to read the raw WSGI environment and pass headers
exactly as received, AND ensure we're reading the truly raw body.
""")

print("\n" + "=" * 70)
print("RECOMMENDED FIX")
print("=" * 70)

print("""
1. Read raw body using request.get_data(cache=False, as_text=False)
   
2. Pass headers as-is from WSGI environment

3. Log hex dump of first 100 bytes to compare

4. Try alternative: Use request.stream.read() directly

Let me check if there's a Flask/WSGI middleware issue...
""")

# Check if signature looks like base64
import base64
try:
    sig_part = webhook_signature_received.split(',')[1]
    decoded = base64.b64decode(sig_part)
    print(f"\n✓ Received signature IS base64 encoded!")
    print(f"  Base64 part: {sig_part}")
    print(f"  Decoded hex: {decoded.hex()}")
    print(f"  Decoded length: {len(decoded)} bytes")
except Exception as e:
    print(f"\n✗ Signature is NOT base64: {e}")

# Our calculated is hex
print(f"\n⚠️  Our calculation returns HEX, but OpenAI sends BASE64!")
print(f"\nLet's check if that's the issue:")

# Convert our hex to base64
try:
    our_hex = our_calculated.split(',')[1]
    our_bytes = bytes.fromhex(our_hex)
    our_base64 = base64.b64encode(our_bytes).decode()
    our_full_base64 = f"v1,{our_base64}"
    
    print(f"  Our signature in base64: {our_full_base64}")
    print(f"  OpenAI's signature:      {webhook_signature_received}")
    print(f"  Match: {our_full_base64 == webhook_signature_received}")
    
except Exception as e:
    print(f"  Error: {e}")

print("\n" + "=" * 70)
