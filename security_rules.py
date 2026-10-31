import re
import html

# Deterministic patterns for precise attack identification
ATTACK_SIGNATURES = {
    "SQL Injection (SQLi)": {
        "pattern": r"(?i)(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER)\b|--|#|/\*|'\s*OR\s*'\d+'='\d+|'\s*OR\s*1=1)",
        "severity": "Critical",
        "cwe": "CWE-89",
        "countermeasure": "Use Parameterized Queries / Prepared Statements (e.g., cursor.execute('SELECT * FROM users WHERE user=?', (u,))) to guarantee the input is treated as data, never executable code.",
        "code_example": """# Vulnerable:
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")

# Fixed (Prepared Statement):
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))"""
    },
    "Cross-Site Scripting (XSS)": {
        "pattern": r"(?i)(<\s*script[^>]*>|javascript:|onerror\s*=|onload\s*=|document\.cookie|<\s*img[^>]+src=[^>]+>|<\s*svg)",
        "severity": "High",
        "cwe": "CWE-79",
        "countermeasure": "Perform Context-Aware Output Encoding (HTML entity escaping) and implement a strict Content Security Policy (CSP) header.",
        "code_example": """# Vulnerable:
html_output = f"<div>Hello, {user_input}</div>"

# Fixed (HTML Entity Encoding):
import html
safe_output = f"<div>Hello, {html.escape(user_input)}</div>\""""
    },
    "Path Traversal / Local File Inclusion": {
        "pattern": r"(\.\./|\.\.\\|/etc/passwd|windows/system32)",
        "severity": "High",
        "cwe": "CWE-22",
        "countermeasure": "Never allow direct user-controlled file paths. Validate against an explicit whitelist and enforce `os.path.abspath` resolution within a restricted directory.",
        "code_example": """# Vulnerable:
file = open('/var/www/uploads/' + filename)

# Fixed:
safe_name = os.path.basename(filename)
full_path = os.path.join('/var/www/uploads/', safe_name)"""
    }
}

def analyze_payload_rules(user_input: str):
    """Evaluates input against deterministic signatures and extracts vulnerabilities."""
    detected = []
    for attack_name, data in ATTACK_SIGNATURES.items():
        if re.search(data["pattern"], user_input):
            detected.append({
                "Attack Type": attack_name,
                "Severity": data["severity"],
                "CWE Reference": data["cwe"],
                "Recommended Preventive Mechanism": data["countermeasure"],
                "Code Fix": data["code_example"]
            })
    return detected

def sanitize_input(user_input: str) -> str:
    """Demonstrates input sanitization (defense mechanism)."""
    # 1. Escape HTML entities to neutralize XSS
    sanitized = html.escape(user_input)
    # 2. Strip single quotes and semicolons to neutralize rudimentary injection
    sanitized = re.sub(r"['\";#--]", "", sanitized)
    return sanitized