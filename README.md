# Ubuntu Server Security Hardening Script

## Overview

This script is designed to enhance the security of an Ubuntu server by applying various hardening techniques based on the CIS (Center for Internet Security) benchmarks. It automates the process of securing the server and reducing vulnerabilities by configuring system settings, installing essential security tools, and enforcing best practices.

## Features

- **Automatic Security Updates**: Configures the system to automatically install security updates for all packages.
- **Disabling IPv4 Forwarding**: Prevents the server from routing packets between networks.
- **Security Auditing with Lynis**: Installs and runs Lynis to audit the security of the system.
- **USB Device Control**: Disables USB storage devices to prevent unauthorized data access.
- **Kernel Parameter Security**: Sets kernel parameters to improve system security.
- **Audit Logging**: Configures auditd to track changes to sensitive files.
- **Rootkit Detection**: Installs rkhunter to detect potential rootkits and malware.
- **Brute-force Protection**: Installs and configures fail2ban to protect against brute-force attacks.
- **SSH Hardening**: Disables X11 forwarding and password authentication for SSH access.
- **Scheduled Malware Scanning**: Installs ClamAV and schedules daily scans for malware.
- **Command Logging**: Logs all commands executed by users for auditing purposes.

## Prerequisites

- **Operating System**: This script is designed for Ubuntu-based systems.
- **Sudo Access**: Ensure that you have sudo privileges to execute the commands in the script.

## Usage

1. **Clone the Repository**: 
   Clone this repository to your local machine or server.

   ```bash
   git clone https://github.com/diveshjha37/ubuntu-hardening.git
   cd security-hardening-script
   chmod +x Harden-Ubuntu-Server.sh
   Wait for sometime and check the logs for detail infomation..
