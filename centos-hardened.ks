#
# CentOS 7 Hardened
#
#   by Frédéric Pierret (2018)
#
# Source: CIS CentOS-7 Benchmark v2.1.1

install
lang fr_FR.UTF-8
keyboard --vckeymap=fr --xlayouts='fr'
timezone Europe/Paris --isUtc
auth --useshadow --passalgo=sha512          # CIS 5.3.4
firewall --enabled
services --enabled=sshd
eula --agreed
ignoredisk --only-use=sda
reboot

rootpw --lock

# password: user
user --groups=wheel --iscrypted --name=user --password=$6$woi/J64NFABLn3MT$YtDFtYLaf3Lmazkl1bBmAYZOVLG1NCBK.OyvS7ujTAJ/eeIbnCK.XlbhHRFnWTGqmvD/FwsiTVfDqo/b6h1fn0

bootloader --location=mbr --append=" crashkernel=auto"
zerombr
clearpart --all --initlabel
part swap --asprimary --fstype="swap" --size=1024
part /boot --fstype xfs --size=200
part pv.01 --size=1 --grow
volgroup vg_root pv.01
logvol / --fstype xfs --name=root --vgname=vg_root --size=5120
# CIS 1.1.2 - 1.1.5
logvol /tmp --vgname vg_root --name tmp --size=1024 --fsoptions="nodev,nosuid,noexec"
# CIS 1.1.6
logvol /var --vgname vg_root --name var --size=1024
# CIS 1.1.11
logvol /var/log --vgname vg_root --name log --size=1024
# CIS 1.1.12
logvol /var/log/audit --vgname vg_root --name audit --size=1024
# CIS 1.1.13 - 1.1.14
logvol /home --vgname vg_root --name home --size=1024 --grow --fsoptions="nodev"

# We enforce the remove of specific packages in order to prevent possible bad things (e.g. dependencies)
%packages --ignoremissing --excludedocs
@core
grub2
authconfig
systemd
systemd-libs
openssl
vim
firewalld
aide                    # CIS 1.3.1
libselinux              # CIS 1.6.2
ntp                     # CIS 2.2.1.1
ntpdate                 # CIS 2.2.1.1
chrony                  # CIS 2.2.1.1
tcp_wrappers            # CIS 3.4.1
iptables                # CIS 3.6.1
rsyslog                 # CIS 4.2.1
-prelink                # CIS 1.5.4
-setroubleshoot         # CIS 1.6.1.4
-mcstrans               # CIS 1.6.1.5
-ypbind                 # CIS 2.1.1, CIS 2.3.1
-tftp                   # CIS 2.1.6
-xinetd                 # CIS 2.1.7
-xorg-x11-*             # CIS 2.2.2
-avahi-daemon           # CIS 2.2.3
-cups                   # CIS 2.2.4
-dhcp                   # CIS 2.2.5
#-openldap               # CIS 2.2.6
-nfs-utils              # CIS 2.2.7
-rpcbind                # CIS 2.2.7
-bind                   # CIS 2.2.8
-vsftpd                 # CIS 2.2.9
-httpd                  # CIS 2.2.10
-dovecot                # CIS 2.2.11
-smb                    # CIS 2.2.12
-squid                  # CIS 2.2.13
-net-snmp               # CIS 2.2.14
-ypserv                 # CIS 2.2.16
-rsh-server             # CIS 2.2.17
-telnet                 # CIS 2.2.18, CIS 2.3.4
-tftp-server            # CIS 2.2.19
-talk-server            # CIS 2.2.21
-rsh                    # CIS 2.3.2
-talk                   # CIS 2.3.3
-openldap-clients       # CIS 2.3.5
%end

%post --log=/root/postinstall.log

cd /usr/lib/systemd/system
rm default.target
ln -s multi-user.target default.target

# /etc/fstab
# CIS 1.1.7 - 1.10, 1.1.15 - 1.1.17
cat << EOF >> /etc/fstab
/tmp    /var/tmp    none    bind    0 0
none    /dev/shm    tmpfs   nodev,nosuid,noexec 0 0
EOF

# Disable mounting of unneeded filesystems and network protocols
# CIS 1.1.1, CIS 3.5.1 -- 3.5.4
cat << EOF >> /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# CIS 1.1.21
[[ "x$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)" != "x" ]] && \
{ df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t; }

# CIS 1.1.22
systemctl disable autofs

# CIS 1.2.3 (already satisfied but enforced)
sed -i 's/^gpgcheck.*$/gpgcheck=1/' /etc/yum.conf

# CIS 1.3.2
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'

# CIS 1.4.1
grub_cfg='/boot/grub2/grub.cfg'
chown root:root ${grub_cfg}
chmod 600 ${grub_cfg}

# CIS 1.4.2
# Set bootloader password
# Use grub2-mkpasswd-pbkdf2 to generate the password
# Current password hash: toor
cat << EOF2 >> /etc/grub.d/01_users
#!/bin/sh -e

cat << EOF
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.A1B1A42D6CAC656BCDAE99259BBD1FD547FFCEA89420323B6FC4E22FB4B506F2DE3E78EE91160BAC49772B599C2F7D5D4C0949E75087D558F6635B545740C226.39E62C7D3D96DF433CD082712A8CEF40AD7F13E52E614FAE2AE0CEF4ECE3AAD5058782CBE370FB457FB96222FD0F5EAC0BCF4129EEFD9ED2415E88C33B044223
EOF

EOF2

# CIS 1.5.1
# Restrict Core Dumps
echo \* hard core 0 >> /etc/security/limits.conf
echo fs.suid_dumpable = 0 >> /etc/sysctl.conf

# CIS 1.5.3
echo kernel.randomize_va_space = 2 >> /etc/sysctl.conf

# CIS 1.6.1.1
sed -i 's/selinux=0//; s/enforcing=0//' /etc/selinux/config

# CIS 1.6.1.2 (already satisfied but enforced)
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

# CIS 1.6.1.3 (already satisfied but enforced)
sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

# CIS 1.7.1 - 1.7.6 and CIS 5.2.16
[[ -w /etc/motd ]] && rm /etc/motd
[[ -w /etc/issue ]] && rm /etc/issue
[[ -w /etc/issue.net ]] && rm /etc/issue.net
touch /etc/motd /etc/issue /etc/issue.net
chown root:root /etc/motd /etc/issue /etc/issue.net
chmod 644 /etc/motd /etc/issue /etc/issue.net

# CIS 2.2.1.2
echo OPTIONS="-u ntp:ntp" > /etc/sysconfig/ntpd

# CIS 2.2.1.3
echo OPTIONS="-u chrony" > /etc/sysconfig/chronyd

# CIS 2.2.15
sed -i 's/^inet_interfaces.*/inet_interfaces = localhost/' /etc/postfix/main.cf

# CIS 2.2.19
systemctl disable rsyncd

cat << EOF >> /etc/sysctl.conf
net.ipv4.ip_forward = 0                         # CIS 3.1.1
net.ipv4.conf.all.send_redirects = 0            # CIS 3.1.2
net.ipv4.conf.default.send_redirects = 0        # CIS 3.1.2
net.ipv4.conf.all.accept_source_route = 0       # CIS 3.2.1
net.ipv4.conf.default.accept_source_route = 0   # CIS 3.2.1
net.ipv4.conf.all.accept_redirects = 0          # CIS 3.2.2
net.ipv4.conf.default.accept_redirects = 0      # CIS 3.2.2
net.ipv4.conf.all.secure_redirects = 0          # CIS 3.2.3
net.ipv4.conf.default.secure_redirects = 0      # CIS 3.2.3
net.ipv4.conf.all.log_martians = 1              # CIS 3.2.4
net.ipv4.conf.default.log_martians = 1          # CIS 3.2.4
net.ipv4.icmp_echo_ignore_broadcasts = 1        # CIS 3.2.5
net.ipv4.icmp_ignore_bogus_error_responses = 1  # CIS 3.2.6
net.ipv4.conf.all.rp_filter = 1                 # CIS 3.2.7
net.ipv4.conf.default.rp_filter = 1             # CIS 3.2.7
net.ipv4.tcp_syncookies = 1                     # CIS 3.2.8
net.ipv6.conf.all.accept_ra = 0                 # CIS 3.3.1
net.ipv6.conf.default.accept_ra = 0             # CIS 3.3.1
net.ipv6.conf.all.accept_redirects = 0          # CIS 3.3.2
net.ipv6.conf.default.accept_redirects = 0      # CIS 3.3.2
net.ipv6.conf.all.disable_ipv6 = 1              # CIS 3.3.3
EOF

# CIS 3.3.3 (add supplementary rules)
echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network

# CIS 3.4.3
echo "ALL: ALL" >> /etc/hosts.deny

# CIS 3.4.5
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

chown root:root /etc/rsyslog.conf
chmod 600 /etc/rsyslog.conf

# CIS 3.6
systemctl enable firewalld

# CIS 4.1.1.1 Configure Audit Log Storage Size
auditd_conf='/etc/audit/auditd.conf'
sed -i 's/^max_log_file .*$/max_log_file = 1024/' ${auditd_conf}

# CIS 4.1.1.2 Disable system on Audit Log Full
sed -i 's/^space_left_action.*$/space_left_action = email/' ${auditd_conf}
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' ${auditd_conf}
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = halt/' ${auditd_conf}

# CIS 4.1.1.3 Keep All Auditing Information
sed -i 's/^max_log_file_action.*$/max_log_file_action = keep_logs/' ${auditd_conf}

# CIS 4.1.2
systemctl enable auditd

# CIS 4.1.3
sed -i s/'^GRUB_CMDLINE_LINUX="'/'GRUB_CMDLINE_LINUX="audit=1 '/ /etc/default/grub
grub2-mkconfig -o ${grub_cfg}

# CIS 4.1.4 - 4.1.18
cat << EOF >> /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

-e 2
EOF

# CIS 4.2.1.1
systemctl enable rsyslog

# CIS 4.2.1.2
cat << EOF >> /etc/rsyslog.conf
*.emerg                     :omusrmsg:*
mail.*                      -/var/log/mail
mail.info                   -/var/log/mail.info
mail.warning                -/var/log/mail.warn
mail.err                    /var/log/mail.err
news.crit                   -/var/log/news/news.crit
news.err                    -/var/log/news/news.err
news.notice                 -/var/log/news/news.notice
*.=warning;*.=err           -/var/log/warn
*.crit                      /var/log/warn
*.*;mail.none;news.none     -/var/log/messages
local0,local1.*             -/var/log/localmessages
local2,local3.*             -/var/log/localmessages
local4,local5.*             -/var/log/localmessages
local6,local7.*             -/var/log/localmessages
EOF

# CIS 4.2.1.3
echo '$FileCreateMode 0640' >> /etc/rsyslog.conf

# CIS 4.2.4 (uselessly enforced...in cases...)
chown -R root:root /var/log/mail* /var/log/news/news* /var/log/warn /var/log/messages /var/log/localmessages

# CIS 4.3
sed -i "1 i /var/log/boot.log" /etc/logrotate.d/syslog

# CIS 5.1.1
systemctl enable crond

# CIS 5.1.2 - 5.1.7
chown root:root /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod 600 /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# CIS 5.1.8
[[ -w /etc/at.deny ]] && rm /etc/at.deny
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 600 /etc/at.allow /etc/cron.allow

sshd_config='/etc/ssh/sshd_config'
chown root:root ${sshd_config}                                                      # CIS 5.2.1
chmod 600 ${sshd_config}                                                            # CIS 5.2.1
echo Protocol 2 >> ${sshd_config}                                                   # CIS 5.2.2
sed -i "s/\#LogLevel.*/LogLevel INFO/" ${sshd_config}                               # CIS 5.2.3
sed -i "s/X11Forwarding yes/X11Forwarding no/" ${sshd_config}                       # CIS 5.2.4
sed -i "s/\#MaxAuthTries 6/MaxAuthTries 4/" ${sshd_config}                          # CIS 5.2.5
sed -i "s/\#IgnoreRhosts yes/IgnoreRhosts yes/" ${sshd_config}                      # CIS 5.2.6
sed -i "s/\#HostbasedAuthentication no/HostbasedAuthentication no/" ${sshd_config}  # CIS 5.2.7
sed -i "s/\#PermitRootLogin yes/PermitRootLogin no/" ${sshd_config}                 # CIS 5.2.8
sed -i "s/\#PermitEmptyPasswords no/PermitEmptyPasswords no/" ${sshd_config}        # CIS 5.2.9
sed -i "s/\#PermitUserEnvironment no/PermitUserEnvironment no/" ${sshd_config}      # CIS 5.2.10

line_num=$(grep -n "^\# Ciphers and keying" ${sshd_config} | cut -d: -f1)
sed -i "${line_num} a Ciphers aes128-ctr,aes192-ctr,aes256-ctr" ${sshd_config}      # CIS 5.2.11
sed -i "${line_num} a MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" ${sshd_config}  # CIS 5.2.12

sed -i "s/\#ClientAliveInterval 0/ClientAliveInterval 300/" ${sshd_config}          # CIS 5.2.13
sed -i "s/\#ClientAliveCountMax 3/ClientAliveCountMax 0/" ${sshd_config}            # CIS 5.2.13
sed -i "s/\#LoginGraceTime 2m/LoginGraceTime 60/" ${sshd_config}                    # CIS 5.2.14
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" ${sshd_config}                   # CIS 5.2.16

# CIS 5.3.1
pwqual='/etc/security/pwquality.conf'
sed -i 's/^# minlen =.*$/minlen = 14/' ${pwqual}
sed -i 's/^# dcredit =.*$/dcredit = -1/' ${pwqual}
sed -i 's/^# ucredit =.*$/ucredit = -1/' ${pwqual}
sed -i 's/^# ocredit =.*$/ocredit = -1/' ${pwqual}
sed -i 's/^# lcredit =.*$/lcredit = -1/' ${pwqual}

# CIS 5.3.2 - 5.3.3 (password-auth and system-auth do not exist until first boot)
cat << EOF >> /etc/pam.d/password-auth
auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
EOF

cat << EOF >> /etc/pam.d/system-auth
auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
EOF

# CIS 5.3.3
echo password sufficient pam_unix.so remember=5 >> /etc/pam.d/password-auth
echo password sufficient pam_unix.so remember=5 >> /etc/pam.d/system-auth

# CIS 5.4.1.1
login_defs=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}

# CIS 5.4.1.2
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}

# CIS 5.4.1.3
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}

# CIS 5.4.2
for user in $(awk -F: '($3 < 1000) {print $1 }' /etc/passwd) ; do
    if [ $user != "root" ]; then
        usermod -L $user
        if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
            usermod -s /sbin/nologin $user
        fi
    fi
done

# CIS 5.4.3
root_gid="$(id -g root)"
if [[ "${root_gid}" -ne 0 ]] ; then
  usermod -g 0 root
fi

# CIS 5.4.4
bashrc='/etc/bashrc'
line_num=$(grep -n "^[[:space:]]*umask" ${bashrc} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ ${bashrc}

bashprofile='/etc/profile'
line_num=$(grep -n "^[[:space:]]*umask" ${bashprofile} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ ${bashprofile}

# CIS 5.5
cp /etc/securetty /etc/securetty.orig
cat << EOF > /etc/securetty
console
tty1
ttyS0
hvc0
EOF

# CIS 5.6
pam_su='/etc/pam.d/su'
sed -i "s/^\#\(auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid\)/\1/" ${pam_su}
usermod -G wheel root

# CIS 6.1.2
chmod 644 /etc/passwd
chown root:root /etc/passwd

# CIS 6.1.3
chmod 000 /etc/shadow
chown root:root /etc/shadow

# CIS 6.1.4
chmod 644 /etc/group
chown root:root /etc/group

# CIS 6.1.5
chmod 000 /etc/gshadow
chown root:root /etc/gshadow

# CIS 6.1.6
chmod 600 /etc/passwd-
chown root:root /etc/passwd-

# CIS 6.1.7
chmod 600 /etc/shadow-
chown root:root /etc/shadow-

# CIS 6.1.8
chmod 600 /etc/group-
chown root:root /etc/group-

# CIS 6.1.9
chmod 600 /etc/gshadow-
chown root:root /etc/gshadow-

# CIS 6.2.2
sed -i '/^+:/d' /etc/passwd

# CIS 6.2.3
sed -i '/^+:/d' /etc/shadow

# CIS 6.2.4
sed -i '/^+:/d' /etc/group

%end
