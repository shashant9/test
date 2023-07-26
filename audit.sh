echo "made from centos"
echo "##############################" >> audit-report.txt
echo "1.Enable Anacron Daemon" >> audit-report.txt

yum -y install cronie-anacron >> audit-report.txt

echo "2.Enable cron" >> audit-report.txt

systemctl enable crond >> audit-report.txt
chkconfig crond on >> audit-report.txt

echo "3. SKIP..." >> audit-report.txt

echo "4.Secure cron file" >> audit-report.txt

chmod 0770 /var/log/cron  >> audit-report.txt
/bin/chown root /var/log/cron >> audit-report.txt
/bin/chgrp root /var/log/cron >> audit-report.txt


echo "5.permissions and ownership" >> audit-report.txt

rm /etc/cron.deny  >> audit-report.txt
rm /etc/at.deny >> audit-report.txt
touch /etc/cron.allow >> audit-report.txt
touch /etc/at.allow >> audit-report.txt
chmod og-rwx /etc/cron.allow >> audit-report.txt
chmod og-rwx /etc/at.allow >> audit-report.txt
chown root:root /etc/cron.allow >> audit-report.txt
chown root:root /etc/at.allow >> audit-report.txt

echo "6.permissions crontab" >> audit-report.txt

chown root:root /etc/anacrontab  >> audit-report.txt
chmod og-rwx /etc/anacrontab >> audit-report.txt

echo "7.ownership and permissions on /etc/cron.daily" >> audit-report.txt

chown root:root /etc/cron.d >> audit-report.txt
chmod og-rwx /etc/cron.d >> audit-report.txt

echo "8.permissions crontab" >> audit-report.txt

stat -c "%a %u %g" /etc/anacrontab | egrep ".00 0 0"  >> audit-report.txt

echo "9.ownership and permissions on /etc/cron.hourly" >> audit-report.txt
chown root:root /etc/cron.hourly >> audit-report.txt
chmod og-rwx /etc/cron.hourly >> audit-report.txt

echo "10.ownership and permissions on /etc/cron.monthly" >> audit-report.txt
chown root:root /etc/cron.monthly >> audit-report.txt
chmod og-rwx /etc/cron.monthly >> audit-report.txt

echo "11.ownership and permissions on /etc/cron.weekly" >> audit-report.txt
chown root:root /etc/cron.weekly >> audit-report.txt
chmod og-rwx /etc/cron.weekly >> audit-report.txt

echo "12.Ownership and permissions crontab" >> audit-report.txt
chown root:root /etc/crontab >> audit-report.txt
chmod og-rwx /etc/crontab >> audit-report.txt

echo "13.Set User/Group Owner and Permission on /etc/crontab" >> audit-report.txt

echo "$ModLoad imtcp.so $InputTCPServerRun 514" >> /etc/rsyslog.conf
pkill -HUP rsyslogd

echo "14.start rsyslog service " >> audit-report.txt
chkconfig syslog off  >> audit-report.txt
chkconfig rsyslog on  >> audit-report.txt

echo "15.Collect Changes to System Administration Scope" >> audit-report.txt

echo "-w /etc/sudoers -p wa -k scope" >>/etc/audit/audit.rules 
echo "-w /etc/sudoers.d -p wa -k scope" >>/etc/audit/audit.rules 


echo "16.Collect Discretionary Access Control Permission Modification Events" >> audit-report.txt

echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid_=1000 -F auid!=4294967295 -k perm_mod " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid_=1000 -F auid!=4294967295 -k perm_mod " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid_=1000 -F auid!=4294967295 -k perm_mod " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid_=1000 -F auid!=4294967295 -k perm_mod " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid_=1000 -F auid!=4294967295 -k perm_mod " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid_=1000 -F auid!=4294967295 -k perm_mod " >>/etc/audit/audit.rules


echo "17.Collect File Deletion Events by User" >> audit-report.txt

echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid_=500 -F auid!=4294967295 -k delete " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid_=500 -F auid!=4294967295 -k delete " >>/etc/audit/audit.rules


echo "18.Collect Kernel Module Loading and Unloading" >> audit-report.txt

echo "-w /sbin/insmod -p x -k modules" >>/etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules " >>/etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >>/etc/audit/audit.rules
echo "-a always,exit arch=b64 -S init_module -S delete_module -k modules" >>/etc/audit/audit.rules

######################################pkill -HUP -P 1 auditd  >> audit-report.txt

echo "19.Collect Login and Logout Events" >> audit-report.txt

echo "-w /var/log/lastlog -p wa -k logins >>/etc/audit/audit.rules
echo "-w /var/run/faillock/ -p wa -k logins >>/etc/audit/audit.rules

echo "20.Collect Session Initiation Information" >> audit-report.txt

echo "-w /var/run/utmp -p wa -k session " >>/etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k session " >>/etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k session " >>/etc/audit/audit.rules

echo "21.Collect Successful File System Mounts"

echo "-a always,exit -F arch=b64 -S mount -F auid_=500 -F auid!=4294967295 -k mounts " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid_=500 -F auid!=4294967295 -k mounts " >>/etc/audit/audit.rules

echo "22.Collect System Administrator Actions" >> audit-report.txt

echo "-w /var/log/sudo.log -p wa -k actions " >>/etc/audit/audit.rules

echo "23.Collect Unsuccessful Unauthorized Access Attempts to Files" >> audit-report.txt
echo "max_log_file = (MB)" >>/etc/audit/auditd.conf

echo "24.Configure Audit Log Storage Size" >> audit-report.txt
echo " -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid_=500 -F auid!=4294967295 -k access " >>/etc/audit/audit.rules
echo " -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid_=500 -F auid!=4294967295 -k access " >>/etc/audit/audit.rules
echo " -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid_=500 -F auid!=4294967295 -k access " >>/etc/audit/audit.rules
echo " -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid_=500 -F auid!=4294967295 -k access " >>/etc/audit/audit.rules
pkill -HUP -P 1 auditd


echo "25.Configure Logging" >> audit-report.txt
echo "*.emerg                                  :omusrmsg:* " >>  /etc/rsyslog.conf
echo "mail.*                                  -/var/log/mail " >>  /etc/rsyslog.conf
echo "mail.info                               -/var/log/mail.info " >>  /etc/rsyslog.conf
echo "mail.warning                            -/var/log/mail.warn " >>  /etc/rsyslog.conf
echo "mail.err                                 /var/log/mail.err " >>  /etc/rsyslog.conf
echo "news.crit                               -/var/log/news/news.crit " >>  /etc/rsyslog.conf
echo "news.err                                -/var/log/news/news.err " >>  /etc/rsyslog.conf
echo "news.notice                             -/var/log/news/news.notice " >>  /etc/rsyslog.conf
echo "*.=warning;*.=err                       -/var/log/warn " >>  /etc/rsyslog.conf
echo "*.crit                                   /var/log/warn " >>  /etc/rsyslog.conf
echo "*.*;mail.none;news.none                 -/var/log/messages " >>  /etc/rsyslog.conf
echo "local0,local1.*                         -/var/log/localmessages " >>  /etc/rsyslog.conf
echo "local2,local3.*                         -/var/log/localmessages " >>  /etc/rsyslog.conf
echo "local4,local5.*                         -/var/log/localmessages " >>  /etc/rsyslog.conf
echo "local6,local7.*                         -/var/log/localmessages" >>  /etc/rsyslog.conf
pkill -HUP rsyslogd

echo "25.Configure Logrotate"






echo "28.start Auditd service" >> audit-report.txt
chkconfig auditd on  >> audit-report.txt

echo "30.Events recorded which modify System's Mandatory Access Controls" >> audit-report.txt
echo "-w /etc/selinux/ -p wa -k MAC-policy" >>/etc/audit/audit.rules
service auditd restart

echo "32.Install the rsyslog package" >> audit-report.txt
yum -y install rsyslog 
yum -y install syslog-ng

echo "33.Keep All Auditing Information" >> audit-report.txt

echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf


echo "35.Record Events That Modify Date and Time Information" >> audit-report.txt

echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change " >>/etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change " >>/etc/audit/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >>/etc/audit/audit.rules



echo "36.Record Events that Modify the System's Network Environment" >> audit-report.txt

echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >>  /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale " >>  /etc/audit/audit.rules
echo "-w /etc/issue -p wa -k system-locale " >>  /etc/audit/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >>  /etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k system-locale " >>  /etc/audit/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale " >>  /etc/audit/audit.rules



echo "37.Record Events that Modify User/Group Information" >> audit-report.txt

echo "-w /etc/group -p wa -k identity " >>  /etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k identity " >>  /etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity " >>  /etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity " >>  /etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity " >>  /etc/audit/audit.rules
pkill -P 1-HUP auditd


echo "39.Broadcast ICMP requests are ignored" >> audit-report.txt

echo "40.Configure Network Time Protocol (NTP)" >> audit-report.txt

echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery " >> /etc/ntp.conf



echo "42.Run the following command to disable avahi-daemon " >> audit-report.txt
chkconfig avahi-daemon off   >> audit-report.txt


echo "44.Run the following commands to disable Chargen-dgram " >> audit-report.txt

systemctl stop chargen-dgram >> audit-report.txt

echo "46.Run the following command to verify CMSD service" >> audit-report.txt
ps -ef | grep rpc.cmsd | grep -v grep >> audit-report.txt


echo "47.Run the following commands to disable daytime-dgram "  >> audit-report.txt
systemctl stop daytime-dgram >> audit-report.txt


chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig discard-stream off
chkconfig discard-dgram off 



echo "49.Run the following commands to disable discard -dgram and discard -stream" >> audit-report.txt

echo "50.Run the following commands to disable echo-dgram: " >> audit-report.txt

chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig discard-stream off
chkconfig discard-dgram off

echo "51.Run the following commands to disable echo-stream: " >> audit-report.txt

chkconfig echo-dgram off >> audit-report.txt
chkconfig echo-stream off >> audit-report.txt

echo "57.Run the following command to disable:" >> audit-report.txt
 chkconfig nfslock off  >> audit-report.txt
 chkconfig rpcgssd off >> audit-report.txt
 chkconfig rpcbind off >> audit-report.txt
 chkconfig rpcidmapd  off >> audit-report.txt
 chkconfig rpcsvcgssd off >> audit-report.txt

echo "58.Run the following command to verify:" >> audit-report.txt

ps -ef | grep nispasswdd | grep -v grep >> audit-report.txt


echo "60.Run the following commands to disable cups server: " >> audit-report.txt
 chkconfig cups off  >> audit-report.txt

echo "61.Run the following command to disable rhnsd : " >> audit-report.txt
chkconfig rhnsd off  >> audit-report.txt

echo "63.Run the following command to disable the tcpmux-server service :" >> audit-report.txt
 chkconfig tcpmux-server off >> audit-report.txt

echo "64.Run the following command to disable the echo-udp service:" >> audit-report.txt
 chkconfig echo-udp off  >> audit-report.txt

echo "66.Run the following commands to disable Kudzu service:" >> audit-report.txt
chkconfig kudzu off >> audit-report.txt

 echo "67.Run the following command to verify:" >> audit-report.txt
 ps -ef | grep rpc.nisd | grep -v grep >> audit-report.txt

echo "68.Run the following commands to disable portmap service:" >> audit-report.txt
chkconfig portmap off  >> audit-report.txt

echo "69.Run the following commands to disable rstatd:" >> audit-report.txt
chkconfig rstatd off  >> audit-report.txt

echo "70.Run the following commands to disable Rusersd service:" >> audit-report.txt
chkconfig rusersd off  >> audit-report.txt

echo "71.Run the following commands to disable rwalld service:" >> audit-report.txt
chkconfig rwalld off >> audit-report.txt

echo "72.Run the following commands to disable UUCP service:" >> audit-report.txt
chkconfig uucp off >> audit-report.txt

echo "75.Install TCP Wrappers :" >> audit-report.txt
yum -y install tcp_wrappers

echo "77.Run the following command to disable NNTP system setting :" >> audit-report.txt
chkconfig NNTP  off >> audit-report.txt


echo "78.Remove DHCP Server" >> audit-report.txt

yum -y remove dhcp >> audit-report.txt

echo "79.Remove DNS Server" >> audit-report.txt
yum -y remove bind >> audit-report.txt


echo "80.Remove FTP Server" >> audit-report.txt
yum -y remove vsftpd >> audit-report.txt
echo "81	Remove HTTP Server" >> audit-report.txt
yum -y remove httpd >> audit-report.txt
echo "82	Remove NIS Client" >> audit-report.txt
yum -y remove ypbind >> audit-report.txt
echo "84	Remove RSH" >> audit-report.txt
yum -y remove rsh >> audit-report.txt
echo "85	Remove RSH-Server" >> audit-report.txt
yum -y remove rsh-server >> audit-report.txt
echo "86	Remove Samba" >> audit-report.txt
yum -y remove samba >> audit-report.txt
echo "87	Remove SNMP Server" >> audit-report.txt
yum -y remove net-snmp >> audit-report.txt
echo "88	Remove Talk" >> audit-report.txt
yum -y remove talk >> audit-report.txt
echo "89	Remove Talk-Server" >> audit-report.txt
yum -y remove talk-server >> audit-report.txt
echo "90	Remove Telnet-Client" >> audit-report.txt
yum -y remove telnet-client >> audit-report.txt
echo "91	Remove Telnet-Server" >> audit-report.txt
yum -y remove tftp >> audit-report.txt
echo "92	Remove TFTP" >> audit-report.txt
yum -y remove tftp-server >> audit-report.txt
echo "93	Remove TFTP-Server" >> audit-report.txt
yum -y remove xinetd >> audit-report.txt
echo "98	Default Group for Root Account" >> audit-report.txt
usermod -g 0 root >> audit-report.txt
echo "100	Lock Inactive User Accounts" >> audit-report.txt
useradd -D -f 90 >> audit-report.txt



echo "108.Run the following command to set permissions on /etc/group- & /etc/gshadow-: " >> audit-report.txt
 chown root:root /etc/group- >> audit-report.txt
 chmod 600 /etc/group- >> audit-report.txt
 chown root:root /etc/gshadow- >> audit-report.txt
 chmod 600 /etc/gshadow- >> audit-report.txt

echo "109.Run the following chown to set permissions on /etc/gshadow : " >> audit-report.txt
 chown root:root /etc/gshadow >> audit-report.txt
 chmod 000 /etc/gshadow >> audit-report.txt

echo "110.Run the following command to set permissions on /etc/passwd : " >> audit-report.txt
 chown root:root /etc/passwd >> audit-report.txt
 chmod 644 /etc/passwd >> audit-report.txt

echo "111..Run the following command to set permissions on /etc/passwd- &  /etc/shadow- :" >> audit-report.txt
 chown root:root /etc/shadow-  >> audit-report.txt
 chown root:root /etc/passwd- >> audit-report.txt
 chmod 600 /etc/shadow- >> audit-report.txt
 chmod 600 /etc/passwd- >> audit-report.txt

echo "112.Run the following commands to set permissions on /etc/shadow : " >> audit-report.txt
 chown root:root /etc/shadow >> audit-report.txt
 chmod 000 /etc/shadow >> audit-report.txt


echo "122.Set Permissions on /, /usr, /etc, /var: " >> audit-report.txt

chmod 755 / >> audit-report.txt
chmod 755 /usr >> audit-report.txt
chmod 755 /etc >> audit-report.txt
chmod 755 /var >> audit-report.txt

echo "123.Run the following command to set permissions on /etc/group : " >> audit-report.txt
chown root:root /etc/group >> audit-report.txt
chmod 644 /etc/group >> audit-report.txt

echo "124.Run the following commands to set permissions on /etc/hosts.allow : " >> audit-report.txt
chown root:root /etc/hosts.allow >> audit-report.txt
chmod 644 /etc/hosts.allow >> audit-report.txt

echo "125.Run the following commands to set permissions on /etc/hosts.deny : " >> audit-report.txt
chown root:root /etc/hosts.deny >> audit-report.txt
chmod 644 /etc/hosts.deny >> audit-report.txt

echo "126.To secure the /root directory, execute the following command at the shell prompt:" >> audit-report.txt
chmod 0750 /root >> audit-report.txt


echo "129.Run the following commands to set permissions on your grub configuration: " >> audit-report.txt

chown root:root /boot/grub2/grub.conf  >> audit-report.txt
chmod og-rwx /boot/grub2/grub.conf  >> audit-report.txt

echo "131.Run the following commands to set ownership and permissions on /etc/ssh/sshd_config : " >> audit-report.txt
chown root:root /etc/ssh/sshd_config  >> audit-report.txt
chmod og-rwx /etc/ssh/sshd_config >> audit-report.txt

echo "143. Run the following command and verify not output is produced: " >> audit-report.txt
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' >> audit-report.txt

echo "148	Configure ExecShield" >> audit-report.txt
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf

echo "155.Run the following command to verify:" >> audit-report.txt
 ps -ef | grep comsat| grep -v grep >> audit-report.txt

echo "156.Run the following command to disable dovecot server:" >> audit-report.txt
chkconfig dovecot off >> audit-report.txt

echo "157.Run the following command to verify:" >> audit-report.txt
ps -ef | grep gssd | grep -v grep >> audit-report.txt

echo "158.Run the following command to disable squid : " >> audit-report.txt
chkconfig squid off >> audit-report.txt

 echo "160.Run the following command to verify:" >> audit-report.txt
ps -ef | grep kerberos | grep -v grep >> audit-report.txt

 echo "161.Run the following command to verify:" >> audit-report.txt
 ps -ef | grep name | grep -v grep >> audit-report.txt

echo "162.Run the following command to verify:" >> audit-report.txt
  ps -ef | grep rpc.rexd | grep -v grep >> audit-report.txt

echo "163. Run the following command to verify:" >> audit-report.txt
 ps -ef | grep rquotad | grep -v grep >> audit-report.txt

echo "164. Run the following command to verify:" >> audit-report.txt
 ps -ef | grep rpc.sprayd | grep -v grep >> audit-report.txt





echo "177	Install AIDE" >> audit-report.txt
yum -y install aide >> audit-report.txt
aide --init >> audit-report.txt

echo "181	Remove MCS Translation Service (mcstrans)" >> audit-report.txt
yum -y remove mcstrans >> audit-report.txt

echo "182	Remove the X Window System" >> audit-report.txt
yum  -y remove xorg-x11* >> audit-report.txt
echo "195	SETroubleshoot is not installed" >> audit-report.txt
yum -y remove setroubleshoot >> audit-report.txt

echo "195	SETroubleshoot is not installed" >> audit-report.txt
df --local -P | awk if (NR!=1) print $6 | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2_/dev/null | xargs chmod a+t >> audit-report.txt

