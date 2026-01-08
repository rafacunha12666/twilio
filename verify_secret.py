#!/usr/bin/env python3
"""
Verify local .env secret matches Railway logs
"""
import os
try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except:
    pass

local_secret = os.getenv("OPENAI_WEBHOOK_SECRET", "")
if not local_secret:
    print("❌ No OPENAI_WEBHOOK_SECRET found in .env")
    exit(1)

print(f"Local Secret: {local_secret}")
print(f"Masked:       {local_secret[:10]}...{local_secret[-6:]}")
print(f"Length:       {len(local_secret)}")

# Check against Railway log
railway_start = "whsec_16sl"
railway_end = "076DY="

print("\nComparing with Railway Log:")
print(f"Railway starts with '{railway_start}'? {'YES' if local_secret.startswith(railway_start) else 'NO'}")
print(f"Railway ends with   '{railway_end}'?   {'YES' if local_secret.endswith(railway_end) else 'NO'}")

if local_secret.startswith(railway_start) and local_secret.endswith(railway_end):
    print("\n✅ MATCH! The secret seems correct.")
    print("This means Railway is modifying the body content.")
else:
    print("\n❌ MISMATCH! The secret in .env is DIFFERENT from Railway.")
    print(f"Please update OPENAI_WEBHOOK_SECRET in Railway to: {local_secret}")
