# -----  Scripts ----- #

### http://www.techexams.net/forums/security-certifications/110760-oscp-jollyfrogs-tale.html#post941431
1) Recon scripts: Automated recon of a network. This will give us a generic idea of what kind of machines are on the network and the various OS's and possible "sweet spots" to start the exploitation process. Only the top 10-20 ports are scanned but we're scanning the whole /24 range.

2) Mapping scripts: Mapping is where I aggregate the data gathered from the recon scripts and start to make sense of things. This includes relationships between systems and traffic flows. This is a manual step which will be done in Visio manually. I have built a Visio template diagram which I will use for this purpose. Mapping will be a continuous process as I move forward in the lab and the Visio diagram will be updated on an almost daily basis.

3) Remote enumeration scripts: These are scripts which will scan a single system remotely, mostly enumerating ports and shares but also the information FROM those ports. This is where the full 1-65535 ports will be scanned (both TCP and UDP) and where each port is fingerprinted, SMB shares are enumerated, user IDs, SNMP details, FTP banners, OS versions etc

4) Remote Exploits & Privilege Escalation: Here we move from knocking on the door to bashing the door out of its sockets and force entry in to the remote system. This includes remote "point-and-shoot-instant-system-access", FTP brute-force, HTTP directory brute force, SNMP brute force, active exploits against open services, etc

5) Local Enumeration scripts: Once we have entered the machine remotely, we enumerate again, getting as much information from the system as possible. This includes interesting files, bash history, cmd history, environment settings, memory, running services, directory permissions, service permissions, scheduled jobs, weak permissions etc

6) Local Exploits & Privilege escalation: We might have a low level user, or a restricted administrator account, this is where we escalate to full root/system level access. This includes UAC bypass, elevation scripts, local exploits, brute forcing, etc

7) Persistance: This is where we install backdoors to secure our access. We don't want to have to go through the whole steps above again. Things like adding local administrator accounts, setting service to start automatic on boot, putting a pinhole in the firewall service, etc

8) Root Loot scripts: This is where we search the whole system with system/root access for interesting data. This includes stealing hashes from LSA, configuration scripts, SAM/shadow database, cracking MD5 and NTLM, checking currently connected users, checking relationship between this host and other hosts, etc

9) Cleanup: This is where we scrub logfiles, clean exploits, hide backdoors, essentially we "wipe our fingerprints" from the system

10) Update maps and diagrams, and move to another system on point 3)


### NMAP ( http://www.techexams.net/forums/security-certifications/110760-oscp-jollyfrogs-tale.html#post941654 )
1) Start with a recon scan of the network to get an idea of the network:
nmap -Pn -F -sSU -T5 -oX /root/10.1.1.1-254.xml 10.1.1.1-254 | grep -v 'filtered|closed' > /root/quick_recon.txt

2) Then force-scan all ports UDP + TCP per host (takes about 4 minutes per host on a LAN or roughly 17 hours for 254 hosts):
nmap -Pn -sSU -T4 -p1-65535 -oX /root/10.1.1.110.xml 10.1.1.110 | grep -v 'filtered|closed'

3) Then run an intensive scan on the open ports per host, TCP and UDP separately to speed scan up:
tcp: nmap -nvv -Pn -sSV -T1 -p$(cat 10.1.1.110.xml | grep portid | grep protocol=\"tcp\" | cut -d'"' -f4 | paste -sd "," -) --version-intensity 9 -oX /root/10.1.1.110-intense-tcp.xml 10.1.1.110
udp: nmap -nvv -Pn -sUV -T1 -p$(cat 10.1.1.110.xml | grep portid | grep protocol=\"udp\" | cut -d'"' -f4 | paste -sd "," -) --version-intensity 9 -oX /root/10.1.1.110-intense-udp.xml 10.1.1.110

Note: During the lab time, I intend to reset the host before doing a full port scan. I will reset each host before I attack it to ensure that there are no spoilers or backdoors on the host.


# ----- Automation Scripts ----- #

### Folder structure 
https://github.com/keiththome/ptfileprep

### Pentest Notes
https://github.com/averagesecurityguy/ptnotes

# ----- Useful Tools & Apps ----- #

### Terminator (Can log and create shortcuts for commands)
https://gnometerminator.blogspot.com/p/introduction.html

### OneNotes
https://www.keiththome.com/oscp-course-review/

### Common Log Paths
http://www.itninja.com/blog/view/mysql-and-apache-profile-log-path-locations

https://www.explainshell.com/

https://github.com/AnasFullStack/Penetration-Testing-Study-Notes
https://github.com/kyawthiha7/oscp_notes
https://github.com/willc/OSCP-stuff
https://github.com/crsftw/OSCP-cheat-sheet
https://github.com/generaldespair/OSCP
https://github.com/ibr2/OSCP-Prep

# ----- Video Resources ----- #
### Level Up! Practical Windows Privilege Escalation - Andrew Smith
https://www.youtube.com/watch?v=PC_iMqiuIRQ

### Its Too Funky In Here04 Linux privilege escalation for fun profit and all around mischief Jake Willi
https://www.youtube.com/watch?v=dk2wsyFiosg


