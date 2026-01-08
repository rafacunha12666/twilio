#!/usr/bin/env python3
"""
List OpenAI Webhooks and Secrets
"""
import os
import requests
import sys

# Force UTF-8 for output
sys.stdout.reconfigure(encoding='utf-8')

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except:
    pass

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    print("❌ Missing OPENAI_API_KEY")
    sys.exit(1)

print(f"Using API Key: ...{OPENAI_API_KEY[-4:]}")

headers = {"Authorization": f"Bearer {OPENAI_API_KEY}"}
try:
    response = requests.get("https://api.openai.com/v1/webhooks", headers=headers)
except Exception as e:
    print(f"❌ Connection error: {e}")
    sys.exit(1)

if not response.ok:
    print(f"❌ API Error: {response.status_code} {response.text}")
    sys.exit(1)

data = response.json()
webhooks = data.get('data', [])

print(f"\nFound {len(webhooks)} webhooks:")

railway_secret_found = False
target_url = "twilio-production-9007.up.railway.app"

for wh in webhooks:
    wh_id = wh.get('id')
    url = wh.get('url')
    secret = wh.get('secret', '')
    
    print("-" * 50)
    print(f"ID:     {wh_id}")
    print(f"URL:    {url}")
    print(f"Secret: {secret}")
    
    # Check if this is likely the one
    if target_url in url:
        print(">>> THIS LOOKS LIKE THE RAILWAY URL <<<")
        railway_secret_found = secret
    
    # log masked secret from user logs: whsec_16sl...076DY=
    if secret.startswith("whsec_16sl") and secret.endswith("076DY="):
        print(">>> MATCHES LOGGED SECRET MASK <<<")

print("-" * 50)
