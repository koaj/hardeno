####################################
## There are a few things that need to be done to your system to be secure.
## This script will do it all for you.
## We are using `#` for main topics. `##` for subtopics
## and `###` for comments on them
####################################


### run this script as root.
sudo su -


# apparmor
## Ensure AppArmor is installed
apt install apparmor -y
## Enable AppArmor
systemctl enable apparmor
## Start AppArmor
systemctl start apparmor
## Ensure AppArmor is enabled in the bootloader configuration
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="apparmor=1"/g' /etc/default/grub
## Update the bootloader
update-grub
## Ensure all AppArmor Profiles are in enforce or complain mode
aa-enforce /etc/apparmor.d/*


# apt
## Remove deprecated packages
apt autoremove -y
apt autoclean -y
## Install sudo on distro
apt install sudo -y






# crontab
## Right permissions for crontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
## Right permissions cron hourly, daily, weekly, monthly
chown root:root /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
chmod og-rwx /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly



# grub
## Set password for boot loader
### grub2-setpassword
### grub2-mkconfig -o '$(dirname '$(find /boot -type f ( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' ) -exec grep -Pl '^h*(kernelopts=|linux|kernel)' {} ;)')/grub.cfg'
## Permissions for grub2 menu
chown root:root /etc/grub/menu.lst
chmod 0400 /etc/grub/menu.lst

## ICMP Broadcasts Requests
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.d/99-sysctl.conf
## Stop logging ICMP messages
echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.d/99-sysctl.conf
## Disable reverse path filtering
echo "net.ipv4.conf.all.rp_filter=0\nnet.ipv4.conf.default.rp_filter=0" >> /etc/sysctl.d/99-sysctl.conf
## Enable TCP SYN Cookies
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/99-sysctl.conf

# Iptables
## Disable loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
## Disable reverse path filtering
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
## Save iptables rules
iptables-save > /etc/iptables.rules
## Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
## Drop null packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
## Block non common MSS values
iptables -A INPUT -p tcp ! --tcp-flags ALL ACK,RST,SYN,FIN -m congestion --cngset 0x1/0x1 -j DROP
## Block port scans
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP
## Protection against SYN flood attacks
iptables -N syn_floodiptables -A INPUT -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn_flood -j DROPiptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPTiptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
iptables -A INPUT -p icmp -j DROPiptables -A OUTPUT -p icmp -j ACCEPT


# ssh
## Disable SSH password authentication
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
## Disable SSH root login
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
## Enable logging
sed -i 's/^LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config
## Maximum number of tries
sed -i 's/^MaxAuthTries 6/MaxAuthTries 3/g' /etc/ssh/sshd_config
## Login Grace Time
sed -i 's/^LoginGraceTime 120/LoginGraceTime 30/g' /etc/ssh/sshd_config

## Permission for ssh keys
chmod 600 /etc/ssh/ssh_host_*
chmod 600 /etc/ssh/ssh_*_key

# systemd
## Disable automatic service startup
systemctl disable apt-daily.service apt-daily-upgrade.service  apt-daily-upgrade.timer apt-daily.timer

## Disable core dumps
echo "Storage=none\nProcessSizeMax=0" >> /etc/systemd/coredump.conf
### Optional: echo "* hard core 0" >> /etc/security/limits.conf


# systemctl
## Disable ICMP Redirects
echo "net.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
## Rejecting source routed packets
echo "net.ipv4.conf.all.accept_source_route=0\nnet.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.d/99-sysctl.conf
##Ensure core dumps are restricted
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-sysctl.conf


