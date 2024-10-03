#!/bin/bash

# Security Hardening Script for Ubuntu Server
# This script implements basic security hardening as per CIS benchmarks.

# Function to log messages
log_message() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Update the system
log_message "Updating the system..."
apt update && apt upgrade -y

# Ensure APT is configured to install security updates automatically
log_message "Configuring APT to install security updates automatically..."
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades

# Disable root login over SSH
log_message "Disabling root login over SSH..."
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Set password expiration
log_message "Setting password expiration to 90 days..."
chage --maxage 90 root
chage --maxage 90 $(getent passwd | awk -F: '$3 >= 1000 {print $1}') # For non-root users

# Configure password complexity
log_message "Configuring password complexity..."
cat <<EOL >> /etc/pam.d/common-password
password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 ocredit=-1 dcredit=-1
EOL

# Lock inactive user accounts
log_message "Locking inactive user accounts..."
passwd -l $(getent passwd | awk -F: '($3 >= 1000 && $3 <= 60000) {print $1}')

# Ensure firewall is installed and configured
log_message "Installing and configuring UFW (Uncomplicated Firewall)..."
apt install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# Disable unused services
log_message "Disabling unused services..."
systemctl disable avahi-daemon.service
systemctl disable cups.service
systemctl disable slapd.service
systemctl disable rpcbind.service

# Ensure the latest version of OpenSSH is installed
log_message "Installing latest version of OpenSSH..."
apt install openssh-server -y

# Configure SSH to use only strong ciphers
log_message "Configuring SSH to use only strong ciphers..."
cat <<EOL >> /etc/ssh/sshd_config
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256
MACs hmac-sha2-512,hmac-sha2-256
EOL
systemctl restart sshd

# Set system logging level
log_message "Setting system logging level..."
echo 'kern.*     /var/log/kernel.log' >> /etc/rsyslog.conf
systemctl restart rsyslog

# Enable and start fail2ban
log_message "Installing and configuring Fail2Ban..."
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban

# Disable IPv6 if not used
log_message "Disabling IPv6..."
if grep -q 'net.ipv6.conf.all.disable_ipv6' /etc/sysctl.conf; then
    sed -i 's/net.ipv6.conf.all.disable_ipv6.*//g' /etc/sysctl.conf
fi
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Set file permissions for sensitive files
log_message "Setting file permissions for sensitive files..."
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 600 /etc/sudoers
chmod 700 /root

# Enable AppArmor for mandatory access control
log_message "Enabling AppArmor..."
systemctl enable apparmor
systemctl start apparmor

# Install and configure logwatch
log_message "Installing and configuring Logwatch..."
apt install logwatch -y
cat <<EOL >> /etc/cron.daily/00logwatch
#!/bin/bash
logwatch --output mail --mailto root --detail high
EOL
chmod +x /etc/cron.daily/00logwatch

# Configure system audit
log_message "Installing and configuring auditd..."
apt install auditd -y
systemctl enable auditd
systemctl start auditd
cat <<EOL >> /etc/audit/rules.d/audit.rules
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/passwd -p wa -k passwd_changes
EOL
service auditd restart

# Configure SSH idle timeout
log_message "Configuring SSH idle timeout..."
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
systemctl restart sshd

# Enforce login on all user accounts
log_message "Enforcing login for all user accounts..."
cat <<EOL >> /etc/login.defs
LOGIN_RETRIES 3
EOL

# Ensure system is not using weak crypto algorithms
log_message "Disabling weak crypto algorithms..."
cat <<EOL >> /etc/ssh/sshd_config
KexAlgorithms diffie-hellman-group-exchange-sha256
Ciphers aes256-ctr
MACs hmac-sha2-512
EOL
systemctl restart sshd

# Set a system-wide umask
log_message "Setting a system-wide umask..."
echo "umask 027" >> /etc/profile

# Set logging for commands run by root
log_message "Setting up logging for commands run by root..."
echo "export PROMPT_COMMAND='history -a; history -n'" >> /root/.bashrc

# Configure automatic security updates for all packages
log_message "Configuring automatic security updates for all packages..."
apt install -y apt-listbugs
apt install -y debconf-utils
cat <<EOL | debconf-set-selections
apt-listbugs apt-listbugs/reportbug boolean false
EOL

# Disable IPv4 forwarding
log_message "Disabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=0
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

# Install and configure Lynis for security auditing
log_message "Installing and configuring Lynis for security auditing..."
apt install lynis -y
lynis audit system

# Disable USB storage devices
log_message "Disabling USB storage devices..."
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

# Set kernel parameters for security
log_message "Setting kernel parameters for security..."
cat <<EOL >> /etc/sysctl.conf
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
fs.protected_symlinks = 1
fs.protected_regular = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOL
sysctl -p

# Install and enable auditd for tracking access to sensitive files
log_message "Installing and configuring auditd..."
apt install auditd -y
systemctl enable auditd
systemctl start auditd

# Configure auditd to log changes to system files
log_message "Configuring auditd to log changes to system files..."
cat <<EOL >> /etc/audit/rules.d/audit.rules
-w /etc/shadow -p wa -k shadow_changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/sudoers -p wa -k sudoers_changes
EOL
service auditd restart

# Enable AppArmor for mandatory access control
log_message "Enabling AppArmor..."
systemctl enable apparmor
systemctl start apparmor

# Install and configure rkhunter for rootkit detection
log_message "Installing and configuring rkhunter for rootkit detection..."
apt install rkhunter -y
rkhunter --update
rkhunter --propupd

# Configure rkhunter to run daily
log_message "Configuring rkhunter to run daily..."
echo "#!/bin/sh" > /etc/cron.daily/rkhunter
echo "/usr/bin/rkhunter --check" >> /etc/cron.daily/rkhunter
chmod +x /etc/cron.daily/rkhunter

# Install and enable fail2ban to protect against brute-force attacks
log_message "Installing and configuring fail2ban..."
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban

# Disable X11 forwarding in SSH
log_message "Disabling X11 forwarding in SSH..."
echo "X11Forwarding no" >> /etc/ssh/sshd_config
systemctl restart sshd

# Set up SSH key authentication and disable password authentication
log_message "Setting up SSH key authentication and disabling password authentication..."
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
systemctl restart sshd

# Set a daily reboot if necessary (for updates, etc.)
log_message "Setting a daily reboot at 3 AM..."
echo "0 3 * * * root /sbin/shutdown -r now" >> /etc/crontab

# Log all commands executed by users
log_message "Logging all commands executed by users..."
echo "export PROMPT_COMMAND='history -a; history -n'" >> /etc/bash.bashrc

# Limit user sessions
log_message "Limiting user sessions..."
echo "session required pam_limits.so" >> /etc/pam.d/common-session

# Ensure /tmp is mounted with noexec, nosuid, and nodev
log_message "Ensuring /tmp is mounted with noexec, nosuid, and nodev..."
echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
mount -o remount /tmp

# Ensure /var is mounted with noexec, nosuid, and nodev
log_message "Ensuring /var is mounted with noexec, nosuid, and nodev..."
echo "tmpfs /var tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
mount -o remount /var

# Configure SSH to use only strong MACs
log_message "Configuring SSH to use only strong MACs..."
echo "MACs hmac-sha2-256,hmac-sha2-512" >> /etc/ssh/sshd_config
systemctl restart sshd

# Install ClamAV for malware scanning
log_message "Installing ClamAV for malware scanning..."
apt install clamav clamav-daemon -y
systemctl enable clamav-daemon
systemctl start clamav-daemon

# Schedule ClamAV to run daily
log_message "Scheduling ClamAV to run daily..."
echo "0 2 * * * clamav /usr/bin/clamscan -r / --remove" >> /etc/crontab

# Reboot prompt
log_message "Additional security hardening steps completed. Please review the changes and reboot the server."

