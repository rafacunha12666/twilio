#!/usr/bin/env python3
"""Fix the hex to base64 bug in debug_signature_validation"""

filename = "openai_sip_webhook.py"

with open(filename, 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace the hexdigest() line with base64 version
old_code = """            expected_sig = hmac.new(
                secret.encode('utf-8'),
                signed_payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()"""

new_code = """            # CRITICAL: OpenAI uses base64, not hexdigest!
            expected_sig = base64.b64encode(
                hmac.new(
                    secret.encode('utf-8'),
                    signed_payload.encode('utf-8'),
                    hashlib.sha256
                ).digest()
            ).decode()"""

if old_code in content:
    content = content.replace(old_code, new_code)
    
    # Also add base64 import if not already there
    if "import base64" not in content:
        # Add after "import hmac"
        content = content.replace(
            "    import hashlib\n    import hmac\n",
            "    import hashlib\n    import hmac\n    import base64\n"
        )
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"✓ Fixed signature calculation in {filename}")
    print("  Changed from hexdigest() to base64.b64encode(...).decode()")
else:
    print(f"✗ Code pattern not found in {filename}")
    print("  The file may have already been updated or has different formatting")
