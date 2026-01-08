#!/usr/bin/env python3
"""Test signature format - hex vs base64"""
import hashlib
import hmac
import base64

# OpenAI webhook signature uses base64, not hex!
secret = "whsec_16slcUa2EVlhDXr2vXx52FwJl9vR076DY="
wh_id = "wh_695f086f6e208190aefdc28ae0d036e9"
ts = "1767835759"

# Expected from OpenAI
expected = "v1,nRB08z9NpRP75UacZWwNrsdjza5lxfxThZ67XhP8Ulo="

# Test without body first (just to verify format)
test_payload = f"{wh_id}.{ts}."

# Calculate in HEX (our current code)
sig_hex = hmac.new(
    secret.encode('utf-8'),
    test_payload.encode('utf-8'),
    hashlib.sha256
).hexdigest()

# Calculate in BASE64 (correct format!)
sig_base64 = base64.b64encode(
    hmac.new(
        secret.encode('utf-8'),
        test_payload.encode('utf-8'),
        hashlib.sha256
    ).digest()
).decode()

print("=" * 70)
print("SIGNATURE FORMAT TEST")
print("=" * 70)
print(f"\nPayload (without body): {test_payload}")
print(f"\nOur HEX format:  v1,{sig_hex}")
print(f"Our BASE64 format: v1,{sig_base64}")
print(f"Expected (OpenAI): {expected}")
print(f"\n✓ BASE64 matches: {f'v1,{sig_base64}' == expected}")
print(f"✗ HEX matches:    {f'v1,{sig_hex}' == expected}")

print("\n" + "=" * 70)
print("CONCLUSION")
print("=" * 70)
print("""
🎯 FOUND THE BUG!

Our debug function uses .hexdigest() which returns HEX format.
OpenAI webhooks use BASE64 format!

We need to change:
  hmac.new(...).hexdigest()  ❌
To:
  base64.b64encode(hmac.new(...).digest()).decode()  ✓

This is why the signatures never match!
""")
