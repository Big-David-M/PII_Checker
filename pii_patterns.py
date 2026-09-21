"""
PII detection engine — regex-only, fully local, no network, no AI.
"""

import re
import math
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Set, Tuple


@dataclass
class PiiMatch:
    start: int
    end: int
    text: str
    pattern_name: str
    category: str  # "personal" or "system"
    confidence: str  # "high", "medium", "low"
    description: str


@dataclass
class PiiPattern:
    name: str
    regex: str
    category: str
    confidence: str
    description: str
    flags: int = re.IGNORECASE
    validator: Optional[Callable[[str], bool]] = None
    keywords: Optional[List[str]] = None  # require nearby keyword


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

PLACEHOLDER_VALUES = {
    "your_api_key_here", "your_token_here", "your_secret_here",
    "changeme", "change_me", "replace_me", "placeholder",
    "xxxxxxxx", "xxxxxxxxxxxxxxxx", "xxx", "todo",
    "insert_token_here", "insert_key_here", "dummy",
    "example", "test", "sample", "fake", "none", "null",
    "your-api-key", "your-token", "your-secret",
}


def is_placeholder(value: str) -> bool:
    raw = value.strip().strip("\"'")
    if raw.startswith('<') and raw.endswith('>'):
        return True
    if raw.startswith('${') and raw.endswith('}'):
        return True
    if raw.startswith('{{') and raw.endswith('}}'):
        return True
    clean = raw.strip("<>{}$").lower().replace("-", "_")
    if clean in PLACEHOLDER_VALUES:
        return True
    if re.match(r'^[xX]+$', clean):
        return True
    if "your" in clean and ("key" in clean or "token" in clean or "secret" in clean or "pass" in clean):
        return True
    if clean.startswith("insert") and clean.endswith("here"):
        return True
    return False


def not_placeholder(value: str) -> bool:
    return not is_placeholder(value)


def luhn_check(number_str: str) -> bool:
    digits = [int(d) for d in re.sub(r"[\s\-]", "", number_str) if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def aba_check(routing: str) -> bool:
    digits = re.sub(r"[\s\-]", "", routing)
    if len(digits) != 9 or not digits.isdigit():
        return False
    d = [int(c) for c in digits]
    checksum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return checksum % 10 == 0


def ssn_validate(ssn_str: str) -> bool:
    digits = re.sub(r"[\s\-]", "", ssn_str)
    if len(digits) != 9 or not digits.isdigit():
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    if area == 0 or area == 666 or 900 <= area <= 999:
        return False
    if group == 0:
        return False
    if int(digits[5:]) == 0:
        return False
    return True


def vin_validate(vin: str) -> bool:
    vin = vin.upper().strip()
    if len(vin) != 17:
        return False
    transliteration = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
    }
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
    total = 0
    for i, ch in enumerate(vin):
        if ch.isdigit():
            val = int(ch)
        elif ch in transliteration:
            val = transliteration[ch]
        else:
            return False
        total += val * weights[i]
    check = total % 11
    check_char = 'X' if check == 10 else str(check)
    return vin[8] == check_char


def high_entropy_check(value: str) -> bool:
    clean = value.strip().strip("\"'")
    if len(clean) < 16:
        return False
    if is_placeholder(clean):
        return False
    freq = {}
    for c in clean:
        freq[c] = freq.get(c, 0) + 1
    length = len(clean)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy > 3.5


def password_value_check(value: str) -> bool:
    if is_placeholder(value):
        return False
    clean = value.strip().strip("\"'")
    if len(clean) < 4:
        return False
    return True


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PATTERNS: List[PiiPattern] = [
    # ══════════════════════════════════════════════════════════════════════
    # Personal PII
    # ══════════════════════════════════════════════════════════════════════

    PiiPattern(
        name="SSN",
        regex=r"(?<!\d)(\d{3}[-\s]\d{2}[-\s]\d{4})(?!\d)",
        category="personal",
        confidence="high",
        description="Social Security Number (XXX-XX-XXXX)",
        flags=0,
        validator=ssn_validate,
    ),
    PiiPattern(
        name="SSN (no dashes)",
        regex=r"(?<!\d)(\d{9})(?!\d)",
        category="personal",
        confidence="medium",
        description="Possible SSN (9 consecutive digits)",
        flags=0,
        validator=ssn_validate,
        keywords=["ssn", "social security", "social sec", "ss#", "ss #"],
    ),
    PiiPattern(
        name="Credit Card",
        regex=r"(?<!\d)((?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4})(?!\d)",
        category="personal",
        confidence="high",
        description="Credit/debit card number (Visa, MC, Amex, Discover)",
        flags=0,
        validator=luhn_check,
    ),
    PiiPattern(
        name="Email",
        regex=r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}",
        category="personal",
        confidence="high",
        description="Email address",
        flags=0,
    ),
    PiiPattern(
        name="Phone (US)",
        regex=r"(?<!\d)(?:\+?1[\s\-.]?)?\(?[2-9]\d{2}\)?[\s\-.]?[2-9]\d{2}[\s\-.]\d{4}(?!\d)",
        category="personal",
        confidence="high",
        description="US phone number",
        flags=0,
    ),
    PiiPattern(
        name="Routing Number",
        regex=r"(?<!\d)([0-9]{9})(?!\d)",
        category="personal",
        confidence="medium",
        description="Bank routing number (ABA)",
        flags=0,
        validator=aba_check,
        keywords=["routing", "aba", "transit"],
    ),
    PiiPattern(
        name="Date of Birth",
        regex=r"(?:dob|d\.o\.b|date\s*of\s*birth|born|birthday|birth\s*date)[\s:=]*(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4})",
        category="personal",
        confidence="medium",
        description="Date of birth",
    ),
    PiiPattern(
        name="Street Address",
        regex=r"\d{1,6}\s+(?:[A-Z][a-z]+\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Ct|Court|Pl(?:ace)?|Way|Cir(?:cle)?|Pkwy|Parkway|Ter(?:race)?|Hwy|Highway)\.?(?:\s+(?:Apt|Suite|Ste|Unit|#)\s*\d+[A-Za-z]?)?",
        category="personal",
        confidence="medium",
        description="US street address",
        flags=0,
    ),
    PiiPattern(
        name="Zip Code",
        regex=r"(?<!\d)(\d{5}(?:-\d{4})?)(?!\d)",
        category="personal",
        confidence="low",
        description="US ZIP code",
        flags=0,
        keywords=["zip", "postal", "address", "city", "state"],
    ),
    PiiPattern(
        name="US Passport",
        regex=r"(?<!\w)([A-Z]\d{8})(?!\w)",
        category="personal",
        confidence="medium",
        description="US passport number",
        flags=0,
        keywords=["passport", "travel doc"],
    ),
    PiiPattern(
        name="VIN",
        regex=r"(?<!\w)([A-HJ-NPR-Z0-9]{17})(?!\w)",
        category="personal",
        confidence="medium",
        description="Vehicle Identification Number",
        flags=0,
        validator=vin_validate,
    ),
    PiiPattern(
        name="IPv4 Address",
        regex=r"(?<!\d)((?:25[0-5]|2[0-4]\d|1?\d\d?)\.(?:25[0-5]|2[0-4]\d|1?\d\d?)\.(?:25[0-5]|2[0-4]\d|1?\d\d?)\.(?:25[0-5]|2[0-4]\d|1?\d\d?))(?!\d)",
        category="personal",
        confidence="low",
        description="IPv4 address",
        flags=0,
    ),
    PiiPattern(
        name="IPv6 Address",
        regex=r"(?<!\w)((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})(?!\w)",
        category="personal",
        confidence="low",
        description="IPv6 address",
        flags=0,
    ),

    # ══════════════════════════════════════════════════════════════════════
    # System Secrets — Known Prefixes (highest confidence)
    # ══════════════════════════════════════════════════════════════════════

    PiiPattern(
        name="AWS Access Key",
        regex=r"(?<!\w)((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?!\w)",
        category="system",
        confidence="high",
        description="AWS access key ID",
        flags=0,
    ),
    PiiPattern(
        name="AWS Secret Key",
        regex=r"(?:aws_secret_access_key|aws_secret|secret_key)[\s:=\"']+([A-Za-z0-9/+=]{40})(?!\w)",
        category="system",
        confidence="high",
        description="AWS secret access key",
    ),
    PiiPattern(
        name="GitHub Token",
        regex=r"(?<!\w)(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,82}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})(?!\w)",
        category="system",
        confidence="high",
        description="GitHub personal access token",
        flags=0,
    ),
    PiiPattern(
        name="GitLab Token",
        regex=r"(?<!\w)(glpat-[A-Za-z0-9\-_]{20,})(?!\w)",
        category="system",
        confidence="high",
        description="GitLab personal access token",
        flags=0,
    ),
    PiiPattern(
        name="Slack Token",
        regex=r"(?<!\w)(xox[bposaer]-[A-Za-z0-9\-]{10,})(?!\w)",
        category="system",
        confidence="high",
        description="Slack API token",
        flags=0,
    ),
    PiiPattern(
        name="Stripe Key",
        regex=r"(?<!\w)((?:sk|pk|rk)_(?:test|live)_[A-Za-z0-9]{10,})(?!\w)",
        category="system",
        confidence="high",
        description="Stripe API key",
        flags=0,
    ),
    PiiPattern(
        name="SendGrid Key",
        regex=r"(?<!\w)(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?!\w)",
        category="system",
        confidence="high",
        description="SendGrid API key",
        flags=0,
    ),
    PiiPattern(
        name="Twilio Key",
        regex=r"(?<!\w)(SK[0-9a-f]{32})(?!\w)",
        category="system",
        confidence="high",
        description="Twilio API key",
        flags=0,
    ),
    PiiPattern(
        name="Google API Key",
        regex=r"(?<!\w)(AIza[A-Za-z0-9_\\-]{35})(?!\w)",
        category="system",
        confidence="high",
        description="Google API key",
        flags=0,
    ),
    PiiPattern(
        name="npm Token",
        regex=r"(?<!\w)(npm_[A-Za-z0-9]{36})(?!\w)",
        category="system",
        confidence="high",
        description="npm access token",
        flags=0,
    ),
    PiiPattern(
        name="PyPI Token",
        regex=r"(?<!\w)(pypi-[A-Za-z0-9_\-]{50,})(?!\w)",
        category="system",
        confidence="high",
        description="PyPI API token",
        flags=0,
    ),
    PiiPattern(
        name="Databricks Token",
        regex=r"(?<!\w)(dapi[a-f0-9]{32})(?!\w)",
        category="system",
        confidence="high",
        description="Databricks personal access token",
        flags=0,
    ),
    PiiPattern(
        name="Hashicorp Vault Token",
        regex=r"(?<!\w)(hvs\.[A-Za-z0-9_\-]{24,})(?!\w)",
        category="system",
        confidence="high",
        description="HashiCorp Vault token",
        flags=0,
    ),
    PiiPattern(
        name="Discord Token",
        regex=r"(?<!\w)([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,})(?!\w)",
        category="system",
        confidence="high",
        description="Discord bot/user token",
        flags=0,
    ),

    # ══════════════════════════════════════════════════════════════════════
    # System Secrets — Structural patterns
    # ══════════════════════════════════════════════════════════════════════

    PiiPattern(
        name="Private Key Block",
        regex=r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+|ENCRYPTED\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----",
        category="system",
        confidence="high",
        description="Private key block",
    ),
    PiiPattern(
        name="Certificate Block",
        regex=r"-----BEGIN\s+CERTIFICATE-----",
        category="system",
        confidence="medium",
        description="X.509 certificate block",
    ),
    PiiPattern(
        name="JWT",
        regex=r"(?<!\w)(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,})(?!\w)",
        category="system",
        confidence="high",
        description="JSON Web Token",
        flags=0,
    ),
    PiiPattern(
        name="Bearer Token",
        regex=r"(?:Bearer|bearer|BEARER)\s+([A-Za-z0-9_\-.~+/]{8,}=*)",
        category="system",
        confidence="high",
        description="Bearer authentication token",
        flags=0,
    ),
    PiiPattern(
        name="Authorization Header",
        regex=r"(?:Authorization|authorization|AUTHORIZATION)[\s]*[=:]+[\s]*[\"']?((?:Bearer|Basic|Token|Digest)\s+[A-Za-z0-9_\-.~+/=]+)",
        category="system",
        confidence="high",
        description="Authorization header value",
        flags=0,
    ),
    PiiPattern(
        name="Basic Auth (Base64)",
        regex=r"(?:Basic\s+)([A-Za-z0-9+/]{16,}={0,2})(?!\w)",
        category="system",
        confidence="high",
        description="Basic auth base64-encoded credentials",
        flags=0,
    ),
    PiiPattern(
        name="SSH Public Key",
        regex=r"(?<!\w)(ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{40,})",
        category="system",
        confidence="medium",
        description="SSH public key",
        flags=0,
    ),
    PiiPattern(
        name="GCP Service Account",
        regex=r'"type"\s*:\s*"service_account"',
        category="system",
        confidence="high",
        description="GCP service account JSON key file",
    ),
    PiiPattern(
        name="Azure SAS Token",
        regex=r"(?:sig=[A-Za-z0-9%+/=]{20,}[&])|(?:sv=\d{4}-\d{2}-\d{2}[&].*sig=)",
        category="system",
        confidence="high",
        description="Azure Shared Access Signature token",
    ),
    PiiPattern(
        name="Azure Storage Key",
        regex=r"(?:AccountKey|account_key|storage_key)[\s]*[=:]+[\s]*[\"']?([A-Za-z0-9+/]{86}==)",
        category="system",
        confidence="high",
        description="Azure storage account key",
    ),
    PiiPattern(
        name="Hashed Password",
        regex=r"(?<!\w)(\$(?:2[abxy]|1|5|6|argon2[id]?|scrypt)\$[^\s$]{4,}(?:\$[^\s$]+)+)(?!\w)",
        category="system",
        confidence="medium",
        description="Hashed password (bcrypt, SHA, argon2, scrypt)",
        flags=0,
    ),

    # ══════════════════════════════════════════════════════════════════════
    # System Secrets — Connection strings & URLs with credentials
    # ══════════════════════════════════════════════════════════════════════

    PiiPattern(
        name="DB Connection String",
        regex=r"(?:(?:mysql|postgresql|postgres|mongodb|mongodb\+srv|redis|amqp|mssql|jdbc:[a-z]+|sqlserver)://[^\s'\"]+:[^\s@'\"]+@[^\s'\"]+)",
        category="system",
        confidence="high",
        description="Database/service connection string with credentials",
    ),
    PiiPattern(
        name="HTTP URL with Creds",
        regex=r"(?:https?://[A-Za-z0-9_.+\-]+:[^\s@'\"]+@[^\s'\"]+)",
        category="system",
        confidence="high",
        description="HTTP(S) URL with embedded credentials",
    ),
    PiiPattern(
        name="Git URL with Token",
        regex=r"(?:https?://(?:ghp_|glpat-|oauth2:)[^\s@'\"]+@[^\s'\"]+)",
        category="system",
        confidence="high",
        description="Git clone URL with embedded token",
        flags=0,
    ),

    # ══════════════════════════════════════════════════════════════════════
    # System Secrets — Config/code/terminal patterns
    # ══════════════════════════════════════════════════════════════════════

    PiiPattern(
        name="Password in Config",
        regex=r"(?:password|passwd|pwd|secret|credential)[\s]*[=:]+[\s]*[\"']?([^\s\"']{4,})(?=[\"'\s,;\n}]|$)",
        category="system",
        confidence="high",
        description="Password or secret value in config",
        validator=lambda v: password_value_check(v) and not_placeholder(v),
    ),
    PiiPattern(
        name="Generic API Key",
        regex=r"(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?key|app[_\-]?secret|client[_\-]?secret|access[_\-]?token)[\s]*[=:]+[\s]*[\"']?([A-Za-z0-9_\-.]{16,})(?![A-Za-z0-9_\-.])",
        category="system",
        confidence="medium",
        description="API key or secret in configuration",
        validator=not_placeholder,
    ),
    PiiPattern(
        name="Env Var Export (secret)",
        regex=r"(?:export\s+|set\s+|\$env:)(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AUTH|CREDENTIAL|DB_PASS)[_A-Z]*[\s]*=[\s]*[\"']?([^\s\"']{4,})",
        category="system",
        confidence="high",
        description="Environment variable export with secret value",
        validator=not_placeholder,
    ),
    PiiPattern(
        name=".env Secret Value",
        regex=r"^(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AUTH|CREDENTIAL|DATABASE_URL|DB_PASS|MASTER_KEY|ENCRYPTION_KEY)[_A-Z]*=[\s]*[\"']?([^\s\"']{4,})",
        category="system",
        confidence="high",
        description="Secret value in .env file format",
        flags=re.MULTILINE,
        validator=not_placeholder,
    ),
    PiiPattern(
        name="Snowflake Credentials",
        regex=r"(?:snowflake_password|sf_password|SNOWFLAKE_PASSWORD|snow_password|SF_TOKEN|SNOWSQL_PWD)[\s]*[=:]+[\s]*[\"']?([^\s\"']{4,})",
        category="system",
        confidence="high",
        description="Snowflake credential in config",
        validator=not_placeholder,
    ),
    PiiPattern(
        name="Snowflake Connection Params",
        regex=r"(?:account|user|role|warehouse|database)[\s]*[=:]+[\s]*[\"']?([^\s\"',;}{]{3,})",
        category="system",
        confidence="medium",
        description="Snowflake connection parameter",
        keywords=["snowflake", "sf_", "snow", "snowsql", "connector", "snowpark"],
    ),
    PiiPattern(
        name="CLI Password Flag",
        regex=r"(?:--password|--passwd|-p)[\s=]+[\"']?([^\s\"']{4,})",
        category="system",
        confidence="high",
        description="Password passed as CLI flag",
        flags=0,
        validator=not_placeholder,
    ),
    PiiPattern(
        name="CLI Token Flag",
        regex=r"(?:--token|--api-key|--secret|--auth)[\s=]+[\"']?([^\s\"']{8,})",
        category="system",
        confidence="high",
        description="Token/secret passed as CLI flag",
        flags=0,
        validator=not_placeholder,
    ),
    PiiPattern(
        name="curl Auth Header",
        regex=r"""curl\s+.*-[Hh]\s+[\"']?(?:Authorization|X-Api-Key|X-Auth-Token):\s*([^\"'\n]+)""",
        category="system",
        confidence="high",
        description="curl command with auth header",
        flags=0,
    ),
    PiiPattern(
        name="curl -u Credentials",
        regex=r"curl\s+.*-u\s+[\"']?([^\s\"':]+:[^\s\"']+)",
        category="system",
        confidence="high",
        description="curl command with -u user:password",
        flags=0,
    ),
    PiiPattern(
        name="Code String Assignment (secret)",
        regex=r"(?:const|let|var|def|val)\s+(?:[a-z_]*(?:secret|token|password|api_key|apikey|auth|credential|private_key)[a-z_]*)\s*=\s*[\"']([^\"']{8,})[\"']",
        category="system",
        confidence="high",
        description="Hardcoded secret in code variable assignment",
        validator=not_placeholder,
    ),
    PiiPattern(
        name="YAML Secret Value",
        regex=r"^[\s]*(?:password|secret|token|api_key|apikey|private_key|access_key|auth_token|master_key|encryption_key)[\s]*:[\s]+[\"']?([^\s\"'#]{4,})",
        category="system",
        confidence="high",
        description="Secret value in YAML config",
        flags=re.MULTILINE,
        validator=not_placeholder,
    ),
    PiiPattern(
        name="JSON Secret Value",
        regex=r"""[\"'](?:password|secret|token|api_key|apiKey|privateKey|accessKey|auth_token|masterKey|encryptionKey)[\"']\s*:\s*[\"']([^\"']{4,})[\"']""",
        category="system",
        confidence="high",
        description="Secret value in JSON config",
        validator=not_placeholder,
    ),
    PiiPattern(
        name="Generic Secret Assignment",
        regex=r"(?:SECRET|TOKEN|PRIVATE|CREDENTIAL|AUTH)[\s_]*[=:]+[\s]*[\"']?([A-Za-z0-9_\-+/=]{20,})",
        category="system",
        confidence="medium",
        description="Generic secret/token in environment or config",
        flags=0,
        validator=not_placeholder,
    ),
    PiiPattern(
        name="High-Entropy Base64 (near keyword)",
        regex=r"(?:secret|token|key|password|credential|auth)[\s:=]+[\"']?([A-Za-z0-9+/]{32,}={0,2})",
        category="system",
        confidence="medium",
        description="High-entropy base64 string near secret keyword",
        validator=high_entropy_check,
    ),
    PiiPattern(
        name="Kubernetes Secret Data",
        regex=r"(?:^[\s]+[a-zA-Z0-9_\-.]+:\s+)([A-Za-z0-9+/]{20,}={0,2})$",
        category="system",
        confidence="medium",
        description="Base64-encoded value in Kubernetes secret manifest",
        flags=re.MULTILINE,
        keywords=["kind: Secret", "kind: secret", "apiVersion:", "data:"],
    ),

    # ══════════════════════════════════════════════════════════════════════
    # System Secrets — UUIDs & Identifiers
    # ══════════════════════════════════════════════════════════════════════

    PiiPattern(
        name="UUID",
        regex=r"(?<!\w)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?!\w)",
        category="system",
        confidence="medium",
        description="UUID — may contain session, user, or resource identifier",
    ),
    PiiPattern(
        name="Heroku API Key",
        regex=r"(?<!\w)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?!\w)",
        category="system",
        confidence="high",
        description="Heroku API key (UUID format)",
        flags=0,
        keywords=["heroku", "HEROKU_API_KEY"],
    ),
]


def _keyword_nearby(text: str, match_start: int, match_end: int, keywords: List[str], window: int = 80) -> bool:
    context_start = max(0, match_start - window)
    context_end = min(len(text), match_end + window)
    context = text[context_start:context_end].lower()
    return any(kw.lower() in context for kw in keywords)


def scan_text(text: str, enabled_patterns: Optional[Set[str]] = None, min_confidence: str = "low") -> List[PiiMatch]:
    confidence_levels = {"high": 3, "medium": 2, "low": 1}
    min_level = confidence_levels.get(min_confidence, 1)
    matches: List[PiiMatch] = []
    seen_spans: set = set()

    for pattern in PATTERNS:
        if enabled_patterns is not None and pattern.name not in enabled_patterns:
            continue
        if confidence_levels.get(pattern.confidence, 1) < min_level:
            continue

        try:
            compiled = re.compile(pattern.regex, pattern.flags)
        except re.error:
            continue

        for m in compiled.finditer(text):
            matched_text = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            start = m.start(1) if m.lastindex and m.lastindex >= 1 else m.start(0)
            end = m.end(1) if m.lastindex and m.lastindex >= 1 else m.end(0)

            span = (start, end)
            if span in seen_spans:
                continue

            if pattern.keywords:
                if not _keyword_nearby(text, start, end, pattern.keywords):
                    continue

            if pattern.validator:
                if not pattern.validator(matched_text):
                    continue

            seen_spans.add(span)
            matches.append(PiiMatch(
                start=start,
                end=end,
                text=matched_text,
                pattern_name=pattern.name,
                category=pattern.category,
                confidence=pattern.confidence,
                description=pattern.description,
            ))

    matches.sort(key=lambda m: m.start)

    # de-overlap: keep higher confidence match when spans overlap
    filtered: List[PiiMatch] = []
    for match in matches:
        overlaps = False
        for existing in filtered:
            if match.start < existing.end and match.end > existing.start:
                if confidence_levels.get(match.confidence, 1) > confidence_levels.get(existing.confidence, 1):
                    filtered.remove(existing)
                    filtered.append(match)
                overlaps = True
                break
        if not overlaps:
            filtered.append(match)

    filtered.sort(key=lambda m: m.start)
    return filtered


def get_all_pattern_names() -> List[Tuple[str, str, str]]:
    return [(p.name, p.category, p.confidence) for p in PATTERNS]
