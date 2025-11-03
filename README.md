# 🔒 Web Server Log Security Analyzer

**Author:** JHC Kok  
**Project Type:** Security Operations & Threat Detection  
**Technologies:** Python 3, Log Analysis, Pattern Matching, Security Automation  
**Status:** Active Portfolio Project

---

## 📋 Project Overview

This security tool analyzes web server access logs (Apache/Nginx format) to identify potential security threats and suspicious activity patterns. Designed for Security Operations Center (SOC) analysts and security professionals, it automates the detection of common attack vectors targeting web applications.

**Business Value:** In enterprise environments, web servers generate thousands of log entries daily. Manual analysis is time-consuming and error-prone. This tool enables rapid threat identification, reducing incident response time from hours to minutes.

---

## 🎯 Security Threats Detected

### 1. **Brute Force Authentication Attacks**
- Identifies multiple failed login attempts from single IP addresses
- Configurable threshold for alert generation (default: 5 attempts)
- Tracks authentication endpoints (login, signin, admin pages)
- **Use Case:** Early detection of credential stuffing and brute force attacks

### 2. **SQL Injection Attempts**
- Pattern matching for common SQL injection techniques
- Detects: UNION-based, Boolean-based, Time-based attacks
- Identifies obfuscated attack payloads in URLs
- **Use Case:** OWASP Top 10 #1 vulnerability detection

### 3. **Suspicious User Agents**
- Identifies known security scanning tools (SQLMap, Nikto, Nmap, Metasploit)
- Detects automated bots and scrapers
- Flags reconnaissance activity
- **Use Case:** Early warning of pending attacks during reconnaissance phase

### 4. **Anomalous Access Patterns**
- High-volume requests from single IPs (potential DDoS or scanning)
- Unusual traffic spikes indicating automated attacks
- **Use Case:** Network-level threat detection

---

## 🛠️ Technical Implementation

### Core Technologies
- **Language:** Python 3.8+
- **Libraries:** Standard library only (re, sys, datetime, collections, pathlib)
- **Architecture:** Object-oriented design for maintainability and extensibility

### Key Features
- ✅ Zero external dependencies (runs on any Python installation)
- ✅ Processes logs of any size (memory-efficient line-by-line parsing)
- ✅ Comprehensive error handling
- ✅ Detailed security reporting with risk ratings
- ✅ Actionable remediation recommendations

### Algorithm Approach
1. **Parsing:** Regular expression-based log parsing (Apache/Nginx Common Log Format)
2. **Pattern Matching:** Multi-pattern detection using compiled regex for efficiency
3. **Aggregation:** Dictionary-based tracking of IP addresses and threat indicators
4. **Reporting:** Structured output with executive summary and detailed findings

---

## 📦 Installation & Usage

### Prerequisites
```bash
Python 3.8 or higher
No external libraries required
```

### Quick Start
```bash
# Clone or download this repository
# Navigate to project folder
cd web-log-security-analyzer

# Run analysis on a log file
python log_analyzer.py sample_logs/attack_access.log

# Output will be saved as: security_analysis_report.txt
```

### Command Line Options
```bash
python log_analyzer.py <path_to_log_file>

Examples:
  python log_analyzer.py /var/log/apache2/access.log
  python log_analyzer.py nginx_access.log
  python log_analyzer.py sample_logs/attack_access.log
```

---

## 📁 Repository Structure
```
web-log-security-analyzer/
│
├── log_analyzer.py              # Main Python script
├── README.md                    # This file - project overview
├── requirements.txt             # Python dependencies (none required)
│
├── sample_logs/                 # Example log files for testing
│   ├── README.md               # Description of sample logs
│   └── attack_access.log       # Log file containing simulated attacks
│
├── sample_reports/              # Example output reports
│   ├── README.md               # Explanation of reports
│   └── attack_analysis_report.txt  # Sample security analysis report
│
├── incident_reports/            # Security incident analyses
│   ├── README.md               # Incident report documentation
│   └── ddos_icmp_flood_analysis.md # DDoS attack incident analysis
│
└── screenshots/                 # Visual documentation
    ├── tool_running.png        # Tool in action
    └── report_output.png       # Sample report output
```

---

## 🔍 Sample Analysis Results

### Example Output (Console)
```
================================================================================
WEB SERVER LOG SECURITY ANALYZER
Author: JHC Kok | Cybersecurity Portfolio Project
================================================================================

[*] Reading log file: sample_logs/attack_access.log
[+] Successfully parsed 64 log entries

[*] Analyzing failed login attempts (threshold: 5)...
[!] ALERT: Found 3 IP(s) with multiple failed login attempts!
    - 192.168.1.105: 8 failed attempts
    - 10.0.0.88: 8 failed attempts
    - 203.0.113.55: 7 failed attempts

[*] Analyzing for SQL injection attempts...
[+] No SQL injection patterns detected

[*] Analyzing user agents...
[!] ALERT: Found 16 requests with suspicious user agents!
    - Detected patterns: {'sqlmap': 4, 'nikto': 3, 'nmap': 2, 'metasploit': 1}

[*] Analyzing access patterns (threshold: 100 requests)...
[+] No unusual access patterns detected

[*] Generating detailed report: security_analysis_report.txt
[+] Report saved: security_analysis_report.txt
[+] Analysis complete!
```

### Key Findings from Generated Report

**FINDING 1: FAILED LOGIN ATTEMPTS (HIGH Severity)**
- Multiple brute force attempts detected
- Recommendations: Implement rate limiting, enable MFA, block suspicious IPs

**FINDING 2: SUSPICIOUS USER AGENTS (MEDIUM-HIGH Severity)**
- Security scanning tools detected (SQLMap, Nikto, Nmap, Metasploit, Acunetix)
- Indicates reconnaissance activity preceding potential attacks
- Recommendations: Block scanner user agents, investigate scan results, patch vulnerabilities

Full sample reports available in `/sample_reports/` directory.

---

## 💡 Skills Demonstrated

This project showcases the following cybersecurity and technical competencies:

### Security Skills
- ✅ **Log Analysis:** Parsing and analyzing security-relevant log data
- ✅ **Threat Detection:** Pattern recognition for common attack vectors
- ✅ **OWASP Top 10:** Understanding of web application vulnerabilities
- ✅ **Incident Response:** Structured approach to security event analysis
- ✅ **Risk Assessment:** Severity ratings and prioritization

### Technical Skills
- ✅ **Python Programming:** Object-oriented design, regex, file I/O
- ✅ **Automation:** Scripting repetitive security tasks
- ✅ **Regular Expressions:** Complex pattern matching
- ✅ **Data Structures:** Efficient use of dictionaries, counters, lists
- ✅ **Documentation:** Clear technical writing and code comments

### Soft Skills
- ✅ **Attention to Detail:** Identifying subtle attack indicators
- ✅ **Problem Solving:** Systematic approach to threat identification
- ✅ **Communication:** Translating technical findings into actionable reports
- ✅ **Risk Management:** Prioritizing threats by severity

---

## 🎓 Learning & Development

### Concepts Applied
- **NIST Cybersecurity Framework:** Detection (DE) function
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1110 (Brute Force)
- **OWASP Top 10 2021:** A03:2021 - Injection vulnerabilities
- **Security Operations:** SIEM-like analysis and reporting

### Frameworks & Standards
- NIST CSF (Cybersecurity Framework)
- OWASP Top 10 Web Application Security Risks
- Common Log Format (CLF) specification
- Incident response best practices

---

## 🚀 Future Enhancements

Planned improvements for this project:
1. Support for additional log formats (IIS, custom formats)
2. Machine learning-based anomaly detection
3. Real-time monitoring with alerting
4. Integration with SIEM platforms (Splunk, ELK)
5. Threat intelligence feed integration
6. Geographic IP analysis
7. Web dashboard for visualization

---

## 📚 Related Projects

This project is part of a larger cybersecurity portfolio:
- **Project #2:** Python Security Automation Scripts (password analyzer, header checker)
- **Project #3:** Secure Code Review Portfolio (OWASP Top 10 analysis)
- **Incident Reports:** NIST framework-based security incident analyses

---

## 📧 Contact

**Author:** Johan Hendrik Christoffel Kok (JHC Kok)  
**Email:** jhckokpretoria@gmail.com  
**Location:** Centurion, Gauteng, South Africa  
**GitHub:** https://github.com/johankok2  
**LinkedIn:** https://www.linkedin.com/in/johankok-cybersecurity/

---

## 📄 License

This project is open source and available for educational and portfolio purposes.

---

## 🎯 About This Project

This tool was developed as part of my transition from civil/railway engineering to cybersecurity. It demonstrates practical application of concepts learned through the Google Cybersecurity Professional Certificate and extensive self-study in Python programming and web application security.

**Portfolio Context:** This project showcases my ability to identify security threats, automate analysis tasks, and communicate findings effectively - core competencies for SOC Analyst and Security Operations roles.

---

**Last Updated:** November 2025  
**Version:** 1.0  
**Status:** Active Development
```

---

## **FILE 2: requirements.txt** (Main folder)

**Location:** `web-log-security-analyzer\requirements.txt`
```
# Web Server Log Security Analyzer
# Python Dependencies

# This project uses only Python standard library
# No external dependencies required

# Minimum Python version: 3.8+
# To verify your Python version: python --version

# Standard library modules used:
# - re (regular expressions)
# - sys (system operations)
# - datetime (timestamp handling)
# - collections (defaultdict, Counter)
# - pathlib (file path handling)

# If you want to add future enhancements, common security libraries include:
# python-dateutil==2.8.2  # For advanced date parsing
# colorama==0.4.6         # For colored terminal output
# requests==2.31.0        # For API integrations
