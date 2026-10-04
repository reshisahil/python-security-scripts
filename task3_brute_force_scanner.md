# Task 3: Traffic Frequency Analysis & Brute-Force Alerting (set, dict)

    Security Objective: Deduplicate network logs to count total unique source IPs and build a dynamic frequency tracker to detect potential web directory scanners or brute-force attacks exceeding a defined threshold.

    Key Concept: Utilizing Python set() for uniqueness and dict{} key-value pairs to calculate traffic volume per IP.

   # Code Implementation:
    firewall_logs = [
    "192.168.1.50", "10.0.0.5", "192.168.1.50", "172.16.0.8",
    "192.168.1.50", "10.0.0.5", "192.168.1.50", "192.168.1.50"
]

     / Extract unique IPs
unique_ips = set(firewall_logs)
print(f"Total Unique IPs Detected: {len(unique_ips)}")

 / Aggregate traffic count per IP
ip_counts = {}
for ip in firewall_logs:
    if ip in ip_counts:
        ip_counts[ip] += 1
    else:
        ip_counts[ip] = 1

 / Threshold evaluation (>3 requests)
for ip, count in ip_counts.items():
    if count > 3:
        print(f"[SOC ALERT] Brute-Force / Scanning detected from IP: {ip} (Requests: {count})")
