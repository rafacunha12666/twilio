#!/usr/bin/env python3
"""
Debug OpenAI webhook configuration and verify body integrity
"""
import os
import json
import hashlib
import hmac
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except:
    pass

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_WEBHOOK_SECRET = os.getenv("OPENAI_WEBHOOK_SECRET")

if not OPENAI_API_KEY:
    raise SystemExit("Missing OPENAI_API_KEY")

# Import OpenAI SDK
try:
    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_API_KEY)
except ImportError:
    raise SystemExit("Run: pip install openai")

print("=" * 60)
print("OPENAI WEBHOOK DIAGNOSTICS")
print("=" * 60)

# 1. List all webhooks
print("\n1. Listing configured webhooks...")
try:
    import requests
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
    response = requests.get("https://api.openai.com/v1/webhooks", headers=headers)
    
    if response.ok:
        webhooks = response.json()
        print(f"\n   Total webhooks: {len(webhooks.get('data', []))}")
        for wh in webhooks.get('data', []):
            print(f"\n   Webhook ID: {wh.get('id')}")
            print(f"   URL: {wh.get('url')}")
            print(f"   Events: {wh.get('events')}")
            print(f"   Secret (first 10 chars): {wh.get('secret', 'N/A')[:10]}...")
    else:
        print(f"   Failed to list webhooks: {response.status_code} {response.text}")
except Exception as e:
    print(f"   Error listing webhooks: {e}")

# 2. Check saved body file
print("\n2. Checking saved webhook body files...")
saved_files = list(Path(".").glob("webhook_body_*.json"))
if saved_files:
    latest = max(saved_files, key=lambda p: p.stat().st_mtime)
    print(f"\n   Latest saved body: {latest}")
    
    with open(latest, 'rb') as f:
        body_bytes = f.read()
    
    print(f"   Body size: {len(body_bytes)} bytes")
    print(f"   Body SHA256: {hashlib.sha256(body_bytes).hexdigest()}")
    
    # Try to parse as JSON
    try:
        body_json = json.loads(body_bytes)
        print(f"   Valid JSON: ✓")
        print(f"   Event type: {body_json.get('type')}")
        print(f"   Event ID: {body_json.get('id')}")
        
        # Extract headers from filename if possible
        # webhook_body_wh_XXX_timestamp.json
        filename = latest.stem
        parts = filename.split('_')
        if len(parts) >= 3:
            webhook_id = 'wh_' + parts[2]
            print(f"\n   From filename - webhook-id: {webhook_id}")
    except json.JSONDecodeError as e:
        print(f"   Invalid JSON: {e}")
        print(f"   First 200 bytes: {body_bytes[:200]}")
else:
    print("   No saved body files found")

# 3. Manual signature verification with detailed logging
print("\n3. Manual signature verification...")
if OPENAI_WEBHOOK_SECRET and saved_files:
    print(f"\n   Using secret: {OPENAI_WEBHOOK_SECRET[:10]}...{OPENAI_WEBHOOK_SECRET[-6:]}")
    
    # From the logs, we have the headers:
    print("\n   From Railway logs:")
    webhook_id = "wh_695f086f6e208190aefdc28ae0d036e9"
    webhook_timestamp = "1767835759"
    webhook_signature = "v1,nRB08z9NpRP75UacZWwNrsdjza5lxfxThZ67XhP8Ulo="
    
    print(f"   webhook-id: {webhook_id}")
    print(f"   webhook-timestamp: {webhook_timestamp}")
    print(f"   webhook-signature: {webhook_signature}")
    
    # Calculate expected signature
    signed_payload = f"{webhook_id}.{webhook_timestamp}.{body_bytes.decode('utf-8')}"
    expected_sig = hmac.new(
        OPENAI_WEBHOOK_SECRET.encode('utf-8'),
        signed_payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    expected_full = f"v1,{expected_sig}"
    
    print(f"\n   Expected signature: {expected_full}")
    print(f"   Received signature: {webhook_signature}")
    print(f"   Match: {hmac.compare_digest(expected_full, webhook_signature)}")
    
    # Try to diagnose the issue
    print(f"\n4. Diagnostic checks...")
    
    # Check if body has BOM
    if body_bytes[:3] == b'\xef\xbb\xbf':
        print("   ⚠ Body has UTF-8 BOM!")
    
    # Check for different line endings
    if b'\r\n' in body_bytes:
        print(f"   Body contains CRLF (\\r\\n)")
    elif b'\n' in body_bytes:
        print(f"   Body contains LF (\\n)")
    
    # Check encoding
    try:
        body_str = body_bytes.decode('utf-8')
        print(f"   ✓ Body is valid UTF-8")
    except UnicodeDecodeError:
        print(f"   ⚠ Body is NOT valid UTF-8")
    
    # Try alternate signature calculation (maybe Railway normalizes)
    print(f"\n5. Trying alternate signature calculations...")
    
    # Try with normalized JSON (re-serialized)
    try:
        body_json = json.loads(body_bytes)
        normalized = json.dumps(body_json, separators=(',', ':'), sort_keys=False)
        signed_payload_norm = f"{webhook_id}.{webhook_timestamp}.{normalized}"
        expected_sig_norm = hmac.new(
            OPENAI_WEBHOOK_SECRET.encode('utf-8'),
            signed_payload_norm.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        expected_full_norm = f"v1,{expected_sig_norm}"
        
        print(f"   With normalized JSON: {expected_full_norm}")
        print(f"   Match: {hmac.compare_digest(expected_full_norm, webhook_signature)}")
    except:
        pass

print("\n" + "=" * 60)
