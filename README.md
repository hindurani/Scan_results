# Scan_results

Network Port Scanning Project - Elevate Labs Task 1
Task 1: Scan Your Local Network for Open Portsg ipconfig
Overview:
This repository contains the results of Task 1 from the Elevate Labs Cyber Security Internship, focusing on scanning a local network for open ports using Nmap and analyzing the findings.

Tools Used:
Nmap: For port scanning and service detection.
Wireshark: For packet analysis.

Steps Performed:
Installed Nmap from nmap.org.
Found local IP range (e.g., 192.168.1.0/24) using ipconfig.
Ran nmap -sS 192.168.1.0/24 for TCP SYN scan.
Noted IP addresses and open ports (e.g., 192.168.1.49: 135, 139, 445, 8089).
Analyzed TCP packets with Wireshark.
Researched services (e.g., RPC on 135, Splunk on 8089).
Identified security risks and recommended mitigations.
Saved results as scan_results.txt and scan_results.html.

Scan Results:
Example: 192.168.1.49 has ports 135/tcp (RPC), 139/tcp (NetBIOS), 445/tcp (Microsoft-ds), and 8089/tcp (Splunk http).

Security Risks:
Port 135: Vulnerable to RPC exploits if unpatched.
Port 139: Risk of credential theft via NetBIOS.
Port 445: Susceptible to MS17-010 (EternalBlue).
Port 8089: Potential unauthorized access to Splunk.

Recommendations:
Patch systems and disable unused ports.
Secure Splunk with authentication and encryption.
Use firewall rules to restrict access.

Files Included
scan_results.txt: Nmap text output.
scan_results.html: Nmap HTML output.

Submission:
Repository link to be submitted via the Elevate Labs portal.
