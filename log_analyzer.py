#!/usr/bin/env python3
"""
Web Server Log File Analyzer
Author: JHC Kok
Date: January 2025
Purpose: Analyzes Apache/Nginx web server logs for security threats
         including failed login attempts, SQL injection patterns,
         and suspicious user agents.

This tool is designed for Security Operations Center (SOC) analysts
and security professionals to quickly identify potential security
incidents in web server access logs.
"""

import re
import sys
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path


class LogAnalyzer:
    """
    Main class for analyzing web server log files.
    
    This analyzer identifies:
    - Multiple failed login attempts (potential brute force attacks)
    - SQL injection attempt patterns in URLs
    - Suspicious user agents (bots, scanners, known attack tools)
    - Unusual access patterns
    """
    
    def __init__(self, log_file_path):
        """
        Initialize the analyzer with a log file.
        
        Args:
            log_file_path (str): Path to the log file to analyze
        """
        self.log_file_path = Path(log_file_path)
        self.log_entries = []
        self.failed_logins = defaultdict(list)  # IP -> list of failed attempts
        self.sql_injection_attempts = []
        self.suspicious_user_agents = []
        self.ip_access_counts = Counter()  # Count requests per IP
        
        # Define suspicious patterns
        self.sql_patterns = [
            r"union.*select",
            r"select.*from",
            r"insert.*into",
            r"delete.*from",
            r"drop.*table",
            r"exec.*\(",
            r"'.*or.*'.*=.*'",
            r"--",
            r"/\*.*\*/",
            r"xp_cmdshell"
        ]
        
        # Known suspicious user agents
        self.suspicious_agents = [
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "metasploit",
            "burp",
            "acunetix",
            "nessus",
            "openvas",
            "w3af",
            "havij",
            "netcraft",
            "scrapy",
            "python-requests",
            "bot",
            "crawler",
            "spider"
        ]
    
    def parse_log_line(self, line):
        """
        Parse a single log line (Apache/Nginx Common Log Format).
        
        Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
        
        Args:
            line (str): Single line from log file
            
        Returns:
            dict: Parsed log entry or None if parsing fails
        """
        # Regular expression for Apache/Nginx common log format
        pattern = r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (\S+) \S+" (\d+) (\d+|-) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'path': match.group(4),
                'status': int(match.group(5)),
                'size': match.group(6),
                'referer': match.group(7),
                'user_agent': match.group(8),
                'raw_line': line.strip()
            }
        return None
    
    def analyze_file(self):
        """
        Read and parse the entire log file.
        """
        print(f"[*] Reading log file: {self.log_file_path}")
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self.parse_log_line(line)
                    if entry:
                        self.log_entries.append(entry)
                        self.ip_access_counts[entry['ip']] += 1
                    else:
                        # Log parsing failures (might indicate tampering)
                        if line.strip():  # Ignore empty lines
                            print(f"[!] Warning: Could not parse line {line_num}")
            
            print(f"[+] Successfully parsed {len(self.log_entries)} log entries")
        
        except FileNotFoundError:
            print(f"[!] Error: Log file not found: {self.log_file_path}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            sys.exit(1)
    
    def detect_failed_logins(self, threshold=5):
        """
        Detect multiple failed login attempts from same IP.
        
        Failed logins typically return HTTP 401 (Unauthorized) or 403 (Forbidden)
        status codes.
        
        Args:
            threshold (int): Number of failures to trigger alert (default: 5)
        """
        print(f"\n[*] Analyzing failed login attempts (threshold: {threshold})...")
        
        for entry in self.log_entries:
            # Check for authentication failures
            if entry['status'] in [401, 403]:
                # Check if path indicates login endpoint
                if any(keyword in entry['path'].lower() for keyword in ['login', 'signin', 'auth', 'admin']):
                    self.failed_logins[entry['ip']].append({
                        'timestamp': entry['timestamp'],
                        'path': entry['path'],
                        'status': entry['status']
                    })
        
        # Find IPs exceeding threshold
        suspicious_ips = {ip: attempts for ip, attempts in self.failed_logins.items() 
                         if len(attempts) >= threshold}
        
        if suspicious_ips:
            print(f"[!] ALERT: Found {len(suspicious_ips)} IP(s) with multiple failed login attempts!")
            for ip, attempts in suspicious_ips.items():
                print(f"    - {ip}: {len(attempts)} failed attempts")
        else:
            print("[+] No suspicious failed login patterns detected")
    
    def detect_sql_injection(self):
        """
        Detect potential SQL injection attempts in URLs.
        
        Searches for common SQL injection patterns in request paths.
        """
        print("\n[*] Analyzing for SQL injection attempts...")
        
        for entry in self.log_entries:
            path_lower = entry['path'].lower()
            
            # Check each SQL pattern
            for pattern in self.sql_patterns:
                if re.search(pattern, path_lower, re.IGNORECASE):
                    self.sql_injection_attempts.append({
                        'ip': entry['ip'],
                        'timestamp': entry['timestamp'],
                        'path': entry['path'],
                        'pattern': pattern,
                        'status': entry['status']
                    })
                    break  # Only count once per entry
        
        if self.sql_injection_attempts:
            print(f"[!] ALERT: Found {len(self.sql_injection_attempts)} potential SQL injection attempts!")
            # Show unique IPs
            unique_ips = set(attempt['ip'] for attempt in self.sql_injection_attempts)
            print(f"    - From {len(unique_ips)} unique IP address(es)")
        else:
            print("[+] No SQL injection patterns detected")
    
    def detect_suspicious_user_agents(self):
        """
        Detect suspicious or malicious user agents.
        
        Identifies known security scanning tools, bots, and automated attack tools.
        """
        print("\n[*] Analyzing user agents...")
        
        for entry in self.log_entries:
            user_agent_lower = entry['user_agent'].lower()
            
            # Check against known suspicious agents
            for suspicious in self.suspicious_agents:
                if suspicious in user_agent_lower:
                    self.suspicious_user_agents.append({
                        'ip': entry['ip'],
                        'timestamp': entry['timestamp'],
                        'user_agent': entry['user_agent'],
                        'path': entry['path'],
                        'matched_pattern': suspicious
                    })
                    break
        
        if self.suspicious_user_agents:
            print(f"[!] ALERT: Found {len(self.suspicious_user_agents)} requests with suspicious user agents!")
            # Show unique patterns
            patterns = Counter(ua['matched_pattern'] for ua in self.suspicious_user_agents)
            print(f"    - Detected patterns: {dict(patterns)}")
        else:
            print("[+] No suspicious user agents detected")
    
    def detect_anomalies(self, threshold=100):
        """
        Detect unusual access patterns (potential DDoS or scanning).
        
        Args:
            threshold (int): Number of requests from single IP to trigger alert
        """
        print(f"\n[*] Analyzing access patterns (threshold: {threshold} requests)...")
        
        high_volume_ips = {ip: count for ip, count in self.ip_access_counts.items() 
                          if count >= threshold}
        
        if high_volume_ips:
            print(f"[!] ALERT: Found {len(high_volume_ips)} IP(s) with high request volume!")
            for ip, count in sorted(high_volume_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"    - {ip}: {count} requests")
        else:
            print(f"[+] No unusual access patterns detected")
    
    def generate_report(self, output_file='security_analysis_report.txt'):
        """
        Generate a comprehensive security analysis report.
        
        Args:
            output_file (str): Path to save the report
        """
        print(f"\n[*] Generating detailed report: {output_file}")
        
        with open(output_file, 'w') as report:
            # Header
            report.write("=" * 80 + "\n")
            report.write("WEB SERVER LOG SECURITY ANALYSIS REPORT\n")
            report.write("=" * 80 + "\n")
            report.write(f"Analyst: JHC Kok\n")
            report.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report.write(f"Log File: {self.log_file_path}\n")
            report.write(f"Total Entries Analyzed: {len(self.log_entries)}\n")
            report.write("=" * 80 + "\n\n")
            
            # Executive Summary
            report.write("EXECUTIVE SUMMARY\n")
            report.write("-" * 80 + "\n")
            total_threats = (
                len([ip for ip, attempts in self.failed_logins.items() if len(attempts) >= 5]) +
                len(self.sql_injection_attempts) +
                len(self.suspicious_user_agents)
            )
            report.write(f"Total Security Events Detected: {total_threats}\n")
            report.write(f"  - Failed Login Attempts: {sum(len(v) for v in self.failed_logins.values())}\n")
            report.write(f"  - SQL Injection Attempts: {len(self.sql_injection_attempts)}\n")
            report.write(f"  - Suspicious User Agents: {len(self.suspicious_user_agents)}\n\n")
            
            # Detailed Findings - Failed Logins
            report.write("\n" + "=" * 80 + "\n")
            report.write("FINDING 1: FAILED LOGIN ATTEMPTS\n")
            report.write("=" * 80 + "\n")
            if self.failed_logins:
                report.write(f"Severity: MEDIUM to HIGH (depending on frequency)\n")
                report.write(f"Description: Multiple failed authentication attempts detected, indicating\n")
                report.write(f"             possible brute-force attack or credential stuffing.\n\n")
                
                for ip, attempts in sorted(self.failed_logins.items(), 
                                          key=lambda x: len(x[1]), reverse=True)[:20]:
                    report.write(f"\nIP Address: {ip}\n")
                    report.write(f"Total Failed Attempts: {len(attempts)}\n")
                    report.write(f"First Attempt: {attempts[0]['timestamp']}\n")
                    report.write(f"Last Attempt: {attempts[-1]['timestamp']}\n")
                    report.write(f"Targeted Paths:\n")
                    for attempt in attempts[:5]:  # Show first 5
                        report.write(f"  - {attempt['timestamp']} | {attempt['path']} | Status: {attempt['status']}\n")
                    if len(attempts) > 5:
                        report.write(f"  ... and {len(attempts) - 5} more attempts\n")
                
                report.write("\nRECOMMENDATIONS:\n")
                report.write("  1. Implement rate limiting on authentication endpoints\n")
                report.write("  2. Consider blocking IPs with excessive failed attempts\n")
                report.write("  3. Enable multi-factor authentication (MFA)\n")
                report.write("  4. Review authentication logs for successful logins from these IPs\n")
            else:
                report.write("No suspicious failed login patterns detected.\n")
            
            # Detailed Findings - SQL Injection
            report.write("\n" + "=" * 80 + "\n")
            report.write("FINDING 2: SQL INJECTION ATTEMPTS\n")
            report.write("=" * 80 + "\n")
            if self.sql_injection_attempts:
                report.write(f"Severity: HIGH to CRITICAL\n")
                report.write(f"Description: SQL injection patterns detected in request URLs. These attempts\n")
                report.write(f"             could lead to unauthorized database access, data theft, or\n")
                report.write(f"             complete system compromise if successful.\n\n")
                
                for attempt in self.sql_injection_attempts[:20]:  # Show first 20
                    report.write(f"\nIP Address: {attempt['ip']}\n")
                    report.write(f"Timestamp: {attempt['timestamp']}\n")
                    report.write(f"Matched Pattern: {attempt['pattern']}\n")
                    report.write(f"Request Path: {attempt['path']}\n")
                    report.write(f"Response Status: {attempt['status']}\n")
                    report.write("-" * 40 + "\n")
                
                if len(self.sql_injection_attempts) > 20:
                    report.write(f"\n... and {len(self.sql_injection_attempts) - 20} more attempts\n")
                
                report.write("\nRECOMMENDATIONS:\n")
                report.write("  1. URGENT: Review application code for SQL injection vulnerabilities\n")
                report.write("  2. Implement parameterized queries/prepared statements\n")
                report.write("  3. Deploy Web Application Firewall (WAF) if not already in place\n")
                report.write("  4. Block identified attacker IP addresses\n")
                report.write("  5. Conduct immediate security audit of database access controls\n")
            else:
                report.write("No SQL injection patterns detected.\n")
            
            # Detailed Findings - Suspicious User Agents
            report.write("\n" + "=" * 80 + "\n")
            report.write("FINDING 3: SUSPICIOUS USER AGENTS\n")
            report.write("=" * 80 + "\n")
            if self.suspicious_user_agents:
                report.write(f"Severity: MEDIUM to HIGH\n")
                report.write(f"Description: Requests from known security scanning tools or suspicious\n")
                report.write(f"             automated tools detected. May indicate reconnaissance or\n")
                report.write(f"             automated attack attempts.\n\n")
                
                for ua in self.suspicious_user_agents[:20]:
                    report.write(f"\nIP Address: {ua['ip']}\n")
                    report.write(f"Timestamp: {ua['timestamp']}\n")
                    report.write(f"User Agent: {ua['user_agent']}\n")
                    report.write(f"Request Path: {ua['path']}\n")
                    report.write(f"Detected Pattern: {ua['matched_pattern']}\n")
                    report.write("-" * 40 + "\n")
                
                if len(self.suspicious_user_agents) > 20:
                    report.write(f"\n... and {len(self.suspicious_user_agents) - 20} more detections\n")
                
                report.write("\nRECOMMENDATIONS:\n")
                report.write("  1. Block known scanner user agents at firewall/WAF level\n")
                report.write("  2. Investigate whether scanning attempts were successful\n")
                report.write("  3. Review vulnerability scan results and patch identified issues\n")
                report.write("  4. Monitor these IPs for further malicious activity\n")
            else:
                report.write("No suspicious user agents detected.\n")
            
            # Access Pattern Analysis
            report.write("\n" + "=" * 80 + "\n")
            report.write("ACCESS PATTERN ANALYSIS\n")
            report.write("=" * 80 + "\n")
            report.write(f"\nTop 10 Most Active IP Addresses:\n")
            report.write("-" * 40 + "\n")
            for ip, count in self.ip_access_counts.most_common(10):
                report.write(f"{ip:20s} | {count:6d} requests\n")
            
            # Conclusion
            report.write("\n" + "=" * 80 + "\n")
            report.write("CONCLUSION\n")
            report.write("=" * 80 + "\n")
            if total_threats > 0:
                report.write(f"This analysis identified {total_threats} security-relevant events requiring\n")
                report.write(f"immediate attention. Follow the recommendations provided above to mitigate\n")
                report.write(f"identified risks.\n\n")
                report.write(f"Priority Actions:\n")
                if self.sql_injection_attempts:
                    report.write(f"  1. CRITICAL: Address SQL injection vulnerabilities immediately\n")
                if len([ip for ip, v in self.failed_logins.items() if len(v) >= 10]):
                    report.write(f"  2. HIGH: Block IPs with excessive failed login attempts\n")
                if self.suspicious_user_agents:
                    report.write(f"  3. MEDIUM: Investigate scanning activity and patch vulnerabilities\n")
            else:
                report.write(f"No immediate security threats detected in this log file. Continue\n")
                report.write(f"regular monitoring and maintain security best practices.\n")
            
            report.write("\n" + "=" * 80 + "\n")
            report.write("END OF REPORT\n")
            report.write("=" * 80 + "\n")
        
        print(f"[+] Report saved: {output_file}")


def main():
    """
    Main function - entry point for the script.
    """
    print("\n" + "=" * 80)
    print("WEB SERVER LOG SECURITY ANALYZER")
    print("Author: JHC Kok | Cybersecurity Portfolio Project")
    print("=" * 80 + "\n")
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python log_analyzer.py <path_to_log_file>")
        print("\nExample:")
        print("  python log_analyzer.py access.log")
        print("  python log_analyzer.py /var/log/apache2/access.log")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    # Create analyzer instance
    analyzer = LogAnalyzer(log_file)
    
    # Run analysis
    analyzer.analyze_file()
    analyzer.detect_failed_logins(threshold=5)
    analyzer.detect_sql_injection()
    analyzer.detect_suspicious_user_agents()
    analyzer.detect_anomalies(threshold=100)
    
    # Generate comprehensive report
    analyzer.generate_report()
    
    print("\n[+] Analysis complete!")
    print("[+] Review 'security_analysis_report.txt' for detailed findings.\n")


if __name__ == "__main__":
    main()