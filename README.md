Automatic Security Updates: Configured APT to ensure all packages receive security updates automatically.
Disabling IPv4 Forwarding: Prevents unwanted routing of packets.
Lynis Installation: Adds a security auditing tool for ongoing assessment.
USB Device Control: Disables USB storage devices to prevent unauthorized access.
Kernel Parameter Security: Adjusts kernel parameters to enhance system security.
Audit Configuration: Ensures sensitive file changes are logged.
Rootkit Detection with rkhunter: Adds a rootkit detection tool with scheduled checks.
Brute-force Protection with fail2ban: Monitors and blocks malicious IPs.
SSH Hardening: Configured to disable X11 forwarding and password authentication.
Daily Reboot: Schedules daily reboots if needed for maintenance.
Command Logging: Enhances command logging for user activities.
Session Limiting: Limits user sessions to prevent excessive resource use.
Secure Temporary Filesystems: Ensures /tmp and /var are mounted securely.
Strong MACs in SSH: Ensures strong message authentication codes in SSH.
ClamAV for Malware Scanning: Provides malware scanning capabilities with scheduled scans.
Usage
You can append these additional steps directly to your existing hardening script. Make sure to review each section and adapt configurations as necessary for your environment.
