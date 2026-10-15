### Methodology Summary

Every time you open an unknown PCAP, follow this sequence:

1. **Protocol Hierarchy** tells you _what kind of machine_ this is
2. **Endpoints** tell you _who’s suspicious_ (disproportionate traffic volume)
3. **Conversations** tell you _how_ the traffic is structured (parallelism, ports)
4. **Build protocol-specific filters** tell you _what they did_ (HTTP paths, DNS queries, SMB shares, RDP sessions, etc.)
5. **Inspect client/application metadata** tells you _what tool or app generated the traffic_ (User-Agent strings, protocol banners, client names, request patterns)
6. **Reconstruct key sessions and relevant artifacts** tell you _the full content and sequence_ of interesting exchanges (`Follow TCP Stream`, `File > Export Objects > HTTP` for compressed responses, key request/response bodies)
7. **Cross-reference timestamps across hosts/files** connects activity into one timeline and separates cause from effect

---
# 1. Initial Triage 

### Protocol Hierarchy Insights

**web-server.pcap:** 
- 99%+ TCP/HTTP. Only 8 application/x-www-form-urlencoded POST frames.
- Note: Proxy setup captures both ingress (Attacker → Proxy) and forwarded (Proxy → Backend) packets. So 8 POST frames = 4 actual login attempts.

**controller.pcap:** 
- Mix of HTTP REST, MySQL, AMQP, etcd (2379), Memcached (11211). Typical OpenStack control plane.

**Traffic Distribution (Endpoints)**
- Sorting IPv4 endpoints in web-server.pcap immediately flags 117.200.21.26 (97.9% of total traffic).
- TCP Conversations show ~187 parallel short-lived streams hitting :80 within ~22 seconds -> automated threaded scanner.

---

# 2. Attack Reconstruction

### Web Server

```
http.request && ip.src == 117.200.21.26
```

Subdomain Fuzzing:
- User-Agent: Fuzz Faster U Fool v2.1.0-dev (ffuf)
- ~3,500+ GET requests probing *.vantage.tech subdomains.
- Discovers sub-domain: cloud.vantage.tech.

Manual Pivot & Login Brute-Force:
- Attacker switches User-Agent to Chrome on macOS.

```
http.request.method == POST && http.request.uri contains "/dashboard/auth/login" && ip.src == 117.200.21.26
```


**4 total POST attempts:**
09:39:16 - admin:admin -> 200 OK (Failed)
09:39:27 - demo:demo -> 200 OK (Failed)
09:39:33 - root:root -> 200 OK (Failed)
09:40:07 - admin:StrongAdminSecret -> 302 Found (Success)

**Config Download:**
- At 09:40:29, downloads admin-openrc.sh from API access page.
- Stream shows binary payload because response is Gzip-compressed. Used File > Export Objects > HTTP to carve file.

**File leaked:**
Auth URL: [http://134.209.71.220/identity]
Project ID: 9fb84977ff7c4a0baf0d5dbb57e235c7

### Controller & Direct API Exploitation
```
http.request && http.user_agent contains "openstacksdk"
```


- 75 seconds after downloading the OpenRC file (time spent sourcing environment variables in CLI), direct API traffic begins on controller 134.209.71.220.
```
09:41:44 - First CLI call: GET /identity (Keystone service discovery).
09:42:11 / 09:42:27 - Enumerates Keystone users (/identity/v3/users) and Nova compute instances (/compute/v2.1/servers/detail).
09:43:27 - Queries Swift object storage (/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7?format=json). Discovers 3 containers: dev-files, employee-data, user-data.
09:45:23 - Exfiltrates user-details.csv from user-data container (28 PII records).
09:48:02 - Persistence: POST /identity/v3/users creates backdoor user jellibean with password P@$$word.
09:49:15 - Grants jellibean admin role on project 9fb84977ff7c4a0baf0d5dbb57e235c7.
```

---
### TASKS

Task 1

What tool did the attacker use to fuzz the web server?
- Examine the early HTTP GET requests in the web server PCAP and check the User-Agent header to identify automated scanning tools.

```
http.request && ip.src == 117.200.21.26
```
Answer: ffuf@2.1.0-dev


Task 2

Which subdomain did the attacker discover?
- Filter for HTTP traffic sent by the attacker using a standard browser User-Agent right after the fuzzing phase ends, then inspect the Host header.
```
http.request && ip.src == 117.200.21.26 && http.user_agent contains "Chrome"
```
Answer: cloud.vantage.tech


Task 3

How many login attempts did the attacker make before successfully logging in?
- Filter for HTTP POST requests to the login URI from the attacker IP. Check the response status codes to distinguish failed attempts (200 OK re-rendering login page) from the successful attempt (302 Found redirecting to dashboard).
```
http.request.method == POST && http.request.uri contains "/dashboard/auth/login" && ip.src == 117.200.21.26
```
Answer: 3


Task 4

When did the attacker download the OpenStack API remote access config file?
- Look for requests requesting the openrc shell script in the web server PCAP and take the frame arrival timestamp of the GET request.
```
http.request.uri contains "openrc" && ip.src == 117.200.21.26
```
Answer: 2025-07-01 09:40:29

Task 5

When did the attacker first interact with the API on the controller node?
-  In the controller PCAP, filter for requests carrying the OpenStack SDK User-Agent string to find the initial service discovery call timestamp.
```
http.request && http.user_agent contains "openstacksdk"
```
Answer: 2025-07-01 09:41:44


Task 6

What is the project ID of the default project accessed by the attacker?
- Export and view the contents of admin-openrc.sh via File > Export Objects > HTTP, or extract the project ID from the path prefix used in API requests on the controller.
```
http.request.uri contains "openrc" 
```
Answer: 9fb84977ff7c4a0baf0d5dbb57e235c7


Task 7

Which OpenStack service provides authentication and authorization?
Locate the service catalog API call on the controller node and inspect the JSON response body where the service type is identity.
```
http.request.uri == "/identity/v3/services" && http.user_agent contains "openstacksdk"
```
Answer: Keystone


Task 8

What is the endpoint URL of the Swift service?
Locate the endpoints API call on the controller node, inspect the JSON response body for the Swift service ID, and resolve the $(project_id)s template variable using the known project ID.
```
http.request.uri == "/identity/v3/endpoints" && http.user_agent contains "openstacksdk"
```
Answer: http://134.209.71.220:8080/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7


Task 9

How many containers were discovered by the attacker?
Filter for the attacker GET request to the Swift storage account listing URI and check either the X-Account-Container-Count response header or count the items in the JSON array response.

```
http.request.uri contains "AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7?format=json" && ip.src == 117.200.21.26
```

Answer: 3


Task 10

When did the attacker download the sensitive user data file?
Search for the HTTP GET request targeting user-details.csv on the controller node and note the frame arrival timestamp.

```
http.request.uri contains "user-details.csv" && ip.src == 117.200.21.26
```

Answer: 2025-07-01 09:45:23


Task 11

How many user records are in the sensitive user data file?
Follow the TCP stream for the user-details.csv download request and count the total number of data rows in the plaintext CSV response, excluding the header row.

```
http.request.uri contains "user-details.csv" && ip.src == 117.200.21.26
```
Answer: 28


Task 12

What is the username of the new user created for persistence?
Filter for HTTP POST requests sent to the Keystone user creation endpoint and inspect the JSON request body payload for the user name parameter.

```
http.request.method == POST && http.request.uri == "/identity/v3/users"
```
Answer: jellibean


Task 13

What is the password of the new user?
Inspect the same JSON request body payload on the user creation request to retrieve the cleartext password string.

```
http.request.method == POST && http.request.uri == "/identity/v3/users"
```
Answer: P@$$word


Task 14

What is the MITRE ATT&CK technique ID for the persistence method?
Map the observed behavior (creating a new cloud user account in Keystone and assigning admin roles) to the MITRE ATT&CK framework under Persistence.

Answer: T1136.003