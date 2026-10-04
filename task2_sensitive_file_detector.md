# Task 2: Data Normalization & Sensitive Path Detection (.strip(), .lower(), .upper())
```
    Security Objective: Sanitize unformatted log entries containing trailing whitespace/newlines, normalize HTTP verbs and paths to prevent casing bypasses, and trigger critical alerts for unauthorized system file access attempts (e.g., /etc/passwd, /etc/shadow).

    Key Concept: String cleaning with .strip(), case normalization via .lower() / .upper(), and conditional substring matching (if "/etc/" in path:).

    Code Implementation:
``` python
suspicious_logs = [
    ' 10.0.0.15 - - [02/Oct/2026:14:10:01] "GET /index.html HTTP/1.1" 200 \n',
    ' 192.168.1.50 - - [02/Oct/2026:14:10:05] "post /ETC/PASSWD HTTP/1.1" 403 \n',
    ' 172.16.0.8 - - [02/Oct/2026:14:10:12] "Get /etc/shadow HTTP/1.1" 200 \n',
    ' 10.0.0.22 - - [02/Oct/2026:14:10:15] "GET /about.html HTTP/1.1" 200 \n'
]

for log in suspicious_logs:
    clean_log = log.strip()
    tokens = clean_log.split()
    
    ip = tokens[0]
    method = tokens[5].strip('"').upper()
    path = tokens[6].lower()
    
    if "/etc/" in path:
        print(f"[CRITICAL ALERT] IP: {ip} issued {method} to sensitive file: {path}")
