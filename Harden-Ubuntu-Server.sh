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

# Reboot prompt
log_message "Security hardening completed. Please review the changes and reboot the server."
