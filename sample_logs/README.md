# Sample Log Files

This directory contains example web server log files for testing the analyzer.

---

## Files

### attack_access.log
**Purpose:** Demonstrates tool's detection capabilities with simulated security threats

**Contains:**
- Normal legitimate web traffic (baseline)
- 3 sources with multiple failed login attempts (brute force simulation)
- 16 suspicious user agent detections (security scanners: SQLMap, Nikto, Nmap, Metasploit, Acunetix)
- Various attack patterns for comprehensive testing

**Threat Summary:**
- **Failed Logins:** 23 attempts from 3 IPs
- **Reconnaissance:** 16 scanner detections
- **Attack Tools:** SQLMap, Nikto, Nmap, Metasploit, Acunetix, Scrapy

**How to use:**
```bash
python log_analyzer.py sample_logs/attack_access.log
```

**Expected Results:**
- Successfully parses 60+ log entries
- Detects 3 IPs with failed login attempts
- Identifies 16 suspicious user agents
- Generates comprehensive security report

---

## Log Format

All logs follow **Apache/Nginx Common Log Format:**
```
IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
```

**Example:**
```
192.168.1.10 - - [27/Jan/2025:10:15:23 +0200] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**Field Breakdown:**
- **IP:** Source IP address
- **Timestamp:** Date and time of request
- **METHOD:** HTTP method (GET, POST, etc.)
- **Path:** Requested URL path
- **Status:** HTTP response code (200 = success, 401/403 = auth failure, 500 = error)
- **Size:** Response size in bytes
- **Referer:** Previous page URL
- **User-Agent:** Client browser/tool identification

---

## Note on Simulated Data

These are artificially created log files for demonstration purposes:
- IP addresses are from reserved ranges (RFC 5737) or private networks
- No real system data is included
- Attack patterns are simulated for educational purposes
- Safe to share publicly in portfolio

---

## Creating Your Own Test Logs

To test with your own logs:
1. Ensure logs follow Apache/Nginx Common Log Format
2. Place log file in this directory
3. Run: `python log_analyzer.py sample_logs/your_log_file.log`

**Tip:** Remove any comment lines (starting with #) before analysis.
