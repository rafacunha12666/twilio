#!/usr/bin/env python3
"""Rewrite debug_signature_validation with body normalization logic"""

filename = "openai_sip_webhook.py"

new_function = r'''def debug_signature_validation(raw_body: bytes, headers: dict, secrets: list, debug_mode: bool = True) -> None:
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
'''

import re

with open(filename, 'r', encoding='utf-8') as f:
    content = f.read()

# Regex to capture the existing function
# Looks for 'def debug_signature_validation' ... until 'print(f"=== END DEBUG ===\n")'
# This is tricky with regex, simpler to locate start/end lines if regex fails
# But let's try a simpler replacement since we know the structure

# Find start
start_marker = 'def debug_signature_validation(raw_body: bytes, headers: dict, secrets: list, debug_mode: bool = True) -> None:'
end_marker = 'print(f"=== END DEBUG ===\\n")'

start_idx = content.find(start_marker)
if start_idx == -1:
    print("❌ Function not found!")
    exit(1)

# Find end (after start)
# The end marker in the file might look slightly different (escaped chars)
# Let's verify the file content first
end_idx = content.find('=== END DEBUG ===', start_idx) 
if end_idx == -1:
    print("❌ End marker not found!")
    exit(1)

# Find the end of that line
nl_idx = content.find('\n', end_idx) + 1 # +1 to include newline

old_func = content[start_idx:nl_idx]

# Replace
new_content = content.replace(old_func, new_function)

if new_content == content:
    print("❌ No change made (replacement failed)!")
else:
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("✓ Function updated successfully")
