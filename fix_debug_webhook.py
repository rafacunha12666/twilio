#!/usr/bin/env python3
"""Fix DEBUG_WEBHOOK reference in openai_sip_webhook.py"""

filename = "openai_sip_webhook.py"

with open(filename, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the problematic line
old_text = '        if DEBUG_WEBHOOK:'
new_text = '        debug_webhook = os.getenv("DEBUG_WEBHOOK", "false").lower() == "true"\n        if debug_webhook:'

if old_text in content:
    content = content.replace(old_text, new_text, 1)  # Replace only first occurrence
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✓ Replaced DEBUG_WEBHOOK reference in {filename}")
else:
    print(f"✗ Text not found in {filename}")
