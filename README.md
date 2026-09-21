# PII Checker

A standalone desktop app that scans pasted text for PII and system secrets **entirely locally** — no AI, no network calls. If the text is clean, you can send it to CoCo (Cortex Code) via clipboard or CLI.

## Quick Start

```bash
python pii_checker.py
```

**Requirements:** Python 3.8+ with tkinter (included in standard Python installs).

No `pip install` needed — zero external dependencies.

## What It Detects

### Personal PII

| Pattern | Confidence | Validation |
|---------|-----------|------------|
| SSN (XXX-XX-XXXX) | High | Area number rules |
| SSN (9 digits, keyword-triggered) | Medium | Area number + nearby keyword |
| Credit/Debit Card | High | Luhn checksum |
| Email Address | High | RFC pattern |
| US Phone Number | High | Multiple formats |
| Bank Routing Number | Medium | ABA checksum + keyword |
| Date of Birth | Medium | Keyword-triggered |
| Street Address | Medium | Number + street + suffix |
| ZIP Code | Low | Keyword-triggered |
| US Passport Number | Medium | Keyword-triggered |
| VIN | Medium | Check digit validation |
| IPv4 Address | Low | Valid range |
| IPv6 Address | Low | Standard format |

### System Secrets

| Pattern | Confidence | Notes |
|---------|-----------|-------|
| AWS Access Key | High | AKIA prefix |
| AWS Secret Key | High | Keyword + 40-char base64 |
| GitHub Token | High | ghp_, github_pat_, gho_, etc. |
| GitLab Token | High | glpat- prefix |
| Slack Token | High | xox* prefix |
| Private Key Block | High | BEGIN PRIVATE KEY |
| JWT | High | eyJ...base64url.base64url.sig |
| Bearer Token | High | Bearer + token string |
| Connection String | High | protocol://user:pass@host |
| Generic API Key | Medium | api_key=, apikey:, etc. |
| Password in Config | High | password=, secret=, etc. |
| UUID | Low | 8-4-4-4-12 hex (toggleable) |
| Hashed Password | Medium | bcrypt, SHA, argon2, scrypt |
| Azure SAS Token | High | sig= parameter |
| Azure Storage Key | High | AccountKey= pattern |
| SSH Public Key | Medium | ssh-rsa, ssh-ed25519 |
| Stripe Key | High | sk_test_, pk_live_, etc. |
| SendGrid Key | High | SG.xxx.xxx |
| Twilio Key | High | SK + 32 hex chars |
| Google API Key | High | AIza prefix |
| GCP Service Account | High | "type": "service_account" |
| Snowflake Credentials | High | Keyword-triggered |
| Generic Secret | Medium | SECRET=, TOKEN=, etc. |

## How It Works

1. **Paste** text into the main text area
2. **Click Scan** — all detection runs locally via regex
3. **Results** appear in the table below; matches are highlighted in the text:
   - Red = high confidence
   - Yellow = medium confidence
   - Blue = low confidence
4. **Click a result row** to jump to that match in the text
5. If **no PII is found**, the Send buttons activate:
   - **Copy to Clipboard** — copies text for manual paste into CoCo
   - **Send to CoCo** — invokes the `cortex` CLI directly

## Settings

Click the **Settings** button (top right) to:

- Set the CoCo CLI path (default: `cortex`)
- Adjust minimum confidence level (show only high, medium+, or all)
- Toggle individual pattern categories on/off (e.g., disable UUID detection for code-heavy text)

Settings are saved to `~/.pii_checker_config.json`.

## Privacy

All scanning happens locally on your machine. The app never makes network calls for PII detection. The only network activity is when you explicitly click "Send to CoCo", which runs the configured CLI command.

## License

MIT
