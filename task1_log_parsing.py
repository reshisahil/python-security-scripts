# Module 1: Python Log Parsing & Threat Detection Scripts

This module covers Python automation scripts designed to process raw server logs, sanitize messy data, detect sensitive file access attempts, and perform frequency-based threat detection (brute-force/scanning).

---

### 📌 Task 1: Basic Web Log Extraction (`.split()`)
* **Security Objective:** Parse raw Apache access log entries to isolate critical fields like Source IP addresses and requested paths for quick incident triage.
* **Key Concept:** Using Python’s `.split()` to tokenize log strings by whitespace delimiter and iterate over dataset collections using `for` loops.
* **Code Implementation:**
```python
raw_logs = [
    '10.0.0.15 - - [02/Oct/2026:14:10:01] "GET /index.html HTTP/1.1" 200',
    '192.168.1.50 - - [02/Oct/2026:14:10:05] "POST /etc/passwd HTTP/1.1" 403',
    '172.16.0.8 - - [02/Oct/2026:14:10:12] "GET /etc/shadow HTTP/1.1" 200'
]

for log in raw_logs:
    tokens = log.split()
    ip_address = tokens[0]
    requested_path = tokens[6]
    
    print(f"[ALERT] IP: {ip_address} accessed path: {requested_path}")
