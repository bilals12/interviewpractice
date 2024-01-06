# Basic Level

These questions require fundamental knowledge of security concepts and are usually theoretical:

## 1. Encryption and Authentication

**What is the difference between authentication vs authorization name spaces (like multi-tenant clouds or K8)?**

   **authentication**: is the process of verifying the identity of a user or process.

   - password-based authentication, MFA, biometrics, token-based (OAuth tokens).

   - in namespace, authentication is provided at application layer. 

   - eg: user logging into specific domain or namespace within a cloud env must provide creds specific to namespace.

   - edge cases: 

        1. credential stuffing: stolen creds from one namespace to gain unauthorized access to another (reusing passwords across different systems)

        2. token hijacking: tokens can be intercepted or stolen, if transmitted over unencrypted channels. 

   **authorization**: is the process of verifying that the user or process has the necessary permissions to access a resource (permissions + access controls)

   - implemented using ACL (access control lists), RBAC (role based access control), ABAC (attribute based access control)

   - in namespace, authorization defines access levels within the namespace

   - eg: in a K8 cluster, a user might be authenticated to access the cluster but only authorized to perform certain actions within a specific namespace.

   - edge cases:

        1. privesc: exploit vulns to gain higher privs than authorized
        2. role conflicts: conflicting roles within different namespaces can cause ambiguities, which might lead to unintentional access to sensitive data.
   **implications**: 

   - isolation: isolation between namespaces

   - least privilege: ensure users have only the perms necessary within each namespace


**What is the difference between symmetric and asymmetric encryption?**
    
    **symmetric**:

    - single key: same key for encryption + decryption. key must be shared and kept secret.

    - key distribution problem

    - faster than asymmetric encryption (suitable for encrypting large volumes of data)

    - common algos include AES, DES, 3DES

    - data at rest: ideal for encrypting stored data (like db contents)

    - data in transit: used within secure channels (after key exchange) for encrypting data in transit

    - edge cases:

        1. compromise: all data at risk if key is compromised

        2. scalability: managing keys with many users is complex
    
    **asymmetric**:

    - key pair: public key (can be shared) + private key (secret)

    - public key is freely distributed, eliminating key distribution problem

    - slower (computational complexity), less efficient for large volumes

    - common algos include RSA, ECC, DH

    - ensures authenticity (digital signatures)

    - used to securely exchange symmetric keys for encrypted comms (SSL/TLS).

    - edge cases:

        1. key length: short keys vulnerable to attacks, longer keys require more processing power
        
        2. quantum: more vulnerable to quantum computing attacks compared to symmetric keys.


**What’s the difference between Diffie-Hellman and RSA?**
    
    **DH**:
    
    - used for securely exchanging crypto keys over a public channel

    - not used for encryption or signing, only for establishing a shared secret

    - allows 2 parties to generate a public-private key pair and then use their private key and the other's public key to create a shared secret

    - discrete logarithm problem: difficult to deduce the shared secret even if public keys are known.

    - does not provide encryption/decryption functionality

    - forward secrecy: compromise of long-term keys does not compromise past session keys

    - edge cases:

        1. MITM: if initial public keys are not authenticated

        2. quantum computing attacks

    **RSA**:

    - encryption of data and digital signatures

    - key pair (public + private key)

    - large prime number factorization (intense and secure)

    - larger key sizes -> slower performance

    - edge cases:

        1. key generation: proper generation of large prime numbers required

        2. quantum computing attacks


**What is Perfect Forward Secrecy?**

    - past communication sessions remain secure and can't be decrypted retroactively if keys are compromised

    - each session has unique, ephemeral keys for encryption.

    - derived through key exchange algos (DH or ECDH)

    - session keys not based on server's private key (used in SSL/TLS)

    - commonly implemented in SSL/TLS protocols to secure web traffic

    - some implementations may use RSA

    - ephemeral keys created for each session and discarded after session ends (no storage)

    - ephemeral keys created automatically during TLS handshake

    - edge cases:

        1. session key can be intercepted and used to decrypt current session

        2. more resource intensive than using static keys

        3. using weak RNG can make ephemeral keys predictable

        4. not all protocols/cipher suites support PFS

        5. quantum attacks


## 2. Network Level and Logging

**What are common ports involving security, what are the risks and mitigations?**

    - **80 (HTTP)**: 

        1. risk: unencrypted web traffic, intercepting/sniffing data

        2. mitigation: use HTTPS and implement HSTS (http strict transport security) to enforce secure connections

    - **443 (HTTPS)**:

        1. risk: vulnerable to misconfigured SSL/TLS, outdated encryption protocols, cipher suites

        2. mitigation: keep SSL/TLS certs updated, use strong encryption (TLS1.2/1.3), disable older protocols (SSLv3)

    - **20, 21 (FTP)**:

        1. risk: data transmitted in plaintext, vulnerable to interception + unauthorized data access

        2. mitigation: use SFTP (ssh file transfer protocol) or FTPS (ftp secure) for encrypted transfers

    - **22 (SSH)**: 

        1. risk: brute force target, attackers can gain shell access

        2. mitigation: strong passwords, key-based authentication, 2FA, change default port

    - **23 (TELNET)**:

        1. risk: similar to FTP

        2. mitigation: replace with SSH

    - **25 (SMTP)**:

        1. risk: can be exploited to send spam/phishing emails

        2. mitigation: use SMTPS (port 465) for secure emails, implement SPF (sender policy framework), DKIM (domainkeys identified mail), DMARC (domain based message authentication reporting conformance)

    - **53 (DNS)**:

        1. risk: DNS spoofing/poisoning can redirect traffic to malicious sites

        2. mitigation: use DNSSEC for verifying authenticity of DNS data

    - **3389 (RDP)**:

        1. risk: target for brute force/credential stuffing, can grant full control

        2. mitigation: use VPNs, enable NLA (network level auth), limit RDP via firewalls

    extra:

        - change default ports to non standard ports

        - configure firewalls to restrict access to necessary ports

        - regular security audits + monitor network traffic

        - software + firmware updates

        - network segmentation



**What is a subnet and how is it useful in security?**

    - segmentation: dividing a larger network into smaller subnets, each subnet operates as a distinct network within the larger infrastructure

    - IP addressing: range of IP addresses allocated within the network (subnet's network boundary)

    - **subnet mask**: used to divide the IP addresses into a network and host component; defines network range within larger network

    - scheme: contiguous IP addresses (class C: 192.168.1.0 - 192.168.1.255)

    - configured by routers and switches

    - VLANs often used with subnets to enhance network management + security

    - public vs. private: public subnets can interact with the internet, private subnets are for internal network resources

    - security:

        1. containment of threats

        2. reduced attack surface

    - access:

        1. subnets can have specific access controls

        2. enhanced monitoring

    - compliance:

        1. subnets help in segregrating sensitive data

        2. isolating critical servers/dbs -> exposure is limited

    - edge cases:

        1. oversegmentation: network complexity -> difficult to manage

        2. cross-subnet access: misconfigured access controls -> unauthorized access

        3. VPN: understanding how VPNs interact with subnets

**Explain the difference between TCP and UDP. Which is more secure and why?**

    - **TCP**:

        - connection oriented: establishes connection before transmission (3-way handshake)

        - reliable delivery: all packets must be delivered accurately and in the correct order (packet sequencing, acknowledgements, retransmission of lost packets)

        - applications where reliability and order are crucial (HTTPS, FTP, SMTP)

        - more secure than UDP (establishes connection and confirms packet delivery)

        - subject to attacks like SYN flooding, SYNACK spoofing, session hijacking

    - **UDP**:

        - connectionless: sends packets (datagrams) independently

        - unreliable delivery: no acknowledgement, retransmission. no guarantee of delivery, order, integrity

        - applications where speed > reliability (video streaming, online gaming, VoIP)

        - less secure than TCP (susceptible to spoofing/reflection attacks eg: send UDP packets with a forged IP address, leading to a reflection attack)

        - no built-in mechanism for integrity or authenticity

   - What is the TCP three-way handshake?

         - view blog

**What is the purpose of TLS?**

    - encryption: established with a combination of symmetric and asymmetric cryptography.

    - authentication: digital certificates used to ensure parties are authenticated

    - integrity: mechanisms in place to ensure data has not been corrupted/altered during transmission

    - handshake: client and server negotiate crypto algos, key exchanges, authentications

    - record: protocol ensures data is encrypted + decrypted correctly, maintaining integrity

    - versioning: each version enhances security

    - widely used in HTTPS (prevents eavesdropping, tampering, MITM)

    - email encryption (SMTPS, POP3S, IMAPS)

    - used in VPNs, VoIP, file transfers

    challenges:

        - misconfigured TLS (outdated protocols, weak ciphers)

        - cert management: expired, revoked, untrusted certs can compromise security

        - compatibility with older versions

**Difference between IPS and IDS?**

- **IDS**:

    - detection focused: monitors network and system activities for malicious activities/policy violations; surveillance system

    - passive: doesn't alter network traffic. observes + reports

    - NIDS: network based, monitors traffic on entire network

    - HIDS: host based, monitors internals of a computer rather than network packets

    - alerts: notifies admins of suspicious activities but doesn't take action

    - logs: logs info related to detections for forensics

- **IPS**:

    - prevention focused: takes active steps to prevent threats

    - active: placed inline with traffic to control/modify traffic, blocks traffic from malicious IP address

    - NIPS: protects network from threats by examining network traffic

    - HIPS: protects hosts by examining syscalls and state of host

    - automatic: takes action like blocking, rerouting, removing malicious packets

    - dynamic: reconfigures security controls to prevent or mitigate threats

- IDS can be deployed without risk of disruption, IPS requires careful configuration to avoid false positives and network interruptions

- IDS serves as detection layer, IPS acts as prevention/response layer

- advanced: anomaly detection, machine learning


**What is a firewall? How does it work?**

    - traffic filtering: examines and filters traffic (incoming/outgoing) based on predefined rules

    - packet filtering: inspects packets at network layer (source/dest IP, port numbers, protocols)

    - stateful inspection: tracks state of active connections, makes decisions based on context (stateful firewall)

    - application layer: inspects traffic at application layer and makes more sophisticated decisions based on context

    - hardware: physical devices placed between network and gateway

    - software: installed on individual servers/devices

    - cloud: cloud service, protects cloud infrastructure

    - rules: based on security policy

    - network security

    - access control

    - monitoring + logging

    challenges:

        - configuration

        - performance impact

        - evolving threats

        - 0-day attacks


## 3. OWASP Top 10, Pentesting, and/or Web Applications

**Differentiate XSS from CSRF**

    - **XSS**:

        - involves injecting malicious scripts into pages viewed by other users

        - runs in the context of the target browser, allowing attacker to steal cookies, session tokens, etc.

        - stored XSS: malicious script stored on server (db), executed when user accesses compromised page

        - reflected XSS: script is not stored but reflected off a web server, through URL or form input

        - DOM XSS: occurs within DOM, doesn't need to interact with server for execution

        - can lead to information theft, session hijacking, manipulate or deface web content

        - mitigation:

            1. sanitization of user inputs

            2. CSP headers to restrict sources of executable script

            3. encode data output to treat it as data, not executable code

    - **CSRF**:

        - tricks a browser into executing an unwanted action on a site where they're authenticated

        - attacker might send link/form that causes authenticated user to submit a request to another site where they're logged in

        - can result in unauthorized actions performed on behalf of user (breaches, compromise)

        - mitigation:

            1. anti-CSRF tokens in forms, validate requests

            2. same-origin policy restrictions in browsers

            3. strict session management like re-auth for critical actions

    - XSS directly affects UX, CSRF exploits authenticated session without knowledge

    - XSS exploits trust in a website, CSRF exploits trust a website has in a browser

    - XSS: script runs within context of browser

    - CSRF: attack executed at server level, manipulating server into performing actions

    - prevention:

        1. XSS: treat user input as untrusted and handle it carefully

        2. CSRF: ensure every request is genuinely intended by user, through unique tokens


**What is a Server-Side Request Forgery attack?**

    - attacker induces server to make request to unintended location, often internal systems

    - typically achieved by manipulating URLs/HTTP requests

    - might target internal dbs, cloud services, APIs that are accessible from server's network

    - also used to interact with services running on localhost

    - exploitation occurs through vulnerable web apps that don't validate user supplied URLs or inputs in making backend requests

    - can lead to exposure of sensitive data

    - map internal network architecture, identify internal services, other exploitable vulns
    - DoS

    - RCE: when SSRF is combined with other vulns

    - mitigation:

        1. input validation

        2. whitelist allowed resources and deny others

        3. limit server's access to internal resources (strict firewall rules, segmentation)

        4. review + update configurations of apps and servers to avoid misconfigs

        5. monitor + log outbound requests


**What is Same Origin Policy and CORS?**

    - **SOP**:

        - restricts web pages from making requests to different domains than the one that served the web page

        - prevents malicious scripts on one page from obtaining access to sensitive data on another page

        - origin defined by scheme (protocol), host (domain), and port of URL

        - webpage can only request resources from the same origin, unless exceptions explicitly allowed

        - without specific perms, scripts from one origin can't read data from or write data to another origin (preventing XSS)

    - **CORS**:

        - allows restricted resources on webpage to be requested from another domain

        - relaxes the SOP for specific scenarios (flexible web apps)

        - server specifies (through HTTP headers) who can access resources and how (methods, headers, credentials, etc)

        - preflight requests: check if server permits actual requests

    - SOP is a fundamental security model (isolating different origins) and CORS is a controlled way to relax SOP

    - SOP is browser controlled, no configuration needed

    - CORS requires specific setup on the server

    - SOP is ideal for protecting data and preventing XSS

    - CORS is used when a webapp needs to make cross-origin requests (3rd party APIs)



## 4. Databases

**What are the 6 aggregate functions of SQL?**

    1. `count()`: number of rows matching a criterion

        - eg: `SELECT COUNT(*) FROM Customers;` returns number of customers in table

    2. `sum()`: adds up values in column

        - eg: `SELECT SUM(SaleAmount) FROM Sales;` returns total sales amount from table

    3. `avg()`: average value of specified column

        - eg: `SELECT AVG(Price) FROM Products;` returns average price of products from table

    4. `max()`: highest value

        - `SELECT MAX(Score) FROM TestResults;` returns highest score from table

    5. `min()`: lowest value

        - `SELECT MIN(Score) FROM TestResults;` returns lowest score from table

    6. `group_concat()`:

        - concatenates values from column into a single string, using a delimiter

        - `SELECT GROUP_CONCAT(Name) FROM Employees;` returns single string of employee names concatenated together

    considerations:

        - except for `count(*)`, these functions ignore null values

        - resource-intensive on large datasets

        - often used with `GROUP BY` to aggregate data within specific categories


## 5. Tools and Games

   - What is the difference between nmap -ss and nmap -st?

   - How would you filter xyz in Wireshark?

**What is the difference between tcp dump and FWmonitor?**

    - **tcpdump**:

        - command-line packet analyzer

        - users can capture/display TCP/IP and other packets being transmitted/received over a network

        - captures packets at network interface level

        - can filter traffic to show specific packets

        - can be used on almost all *nix OS

        - go-to tool for network debugging

        - provides detailed information about network packets (source/dest IP address, packet size, timestamp, protocol)

        - lacks UI

        - significant system resources

    - **FWmonitor**:

        - specific to check point firewalls

        - used to inspec and debug traffic passing through check point firewall modules

        - designed to capture and display packets specifically handled by check point firewall processes and components

        - allows admins to see how packets are affected by rules

        - check point firewall centric

        - useful for firewall admins and less for general network troubleshooting


## 6. Programming and Code

**How can Github webhooks (automating workflows for repo events) be used in a malicious way?**

    1. unauthorized webhook creation

        - attacker gains write access to repo (compromised creds or perm misconfigs) and creates webhook

        - webhook points to malicious server

        - when repo triggers webhook (eg: push event), it sends repo data to attacker's server

    2. interception + manipulation of webhook data

        - webhooks not using HTTPS or lacking proper validation can be intercepted

        - attacker could intercept webhook requests, read sensitive data, manipulate payload before it reaches intended destination

    3. DDoS

        - attacker creates multiple webhooks in a repo or access various repos to trigger massive amount of traffic to target server

        - webhooks can be config'd to all trigger simultaneously (eg: common event)

    4. code injection

        - webhook set up to trigger CI/CD pipeline or execute script on server

        - if webhook payload or receiving script is not securely coded, it could be exploited to execute malicious code on server running the CI/CD pipeline

    5. repo data leakage

        - attacker modifies existing webhook to point to a controlled server

        - sensitive repo data sent to attacker whenever webhook triggers

    6.  webhook spamming

        - attacker creates webhooks that trigger on common repo events

        - results similar to DDoS

    mitigations:

        1. control + monitor who has the ability to create/modify webhooks in repos

        2. use HTTPS endpoints for webhooks to encrypted transmitted data

        3. implement signature verification on receiving end of webhook to validate payloads

        4. review + audit webhooks configured in repos

        5. least privilege principle to account/service that handles webhook actions

        6. ensure scripts/process triggered by webhooks do not expose vulns


**Slack? [Referring to Slack security]**

    1. phishing

        - attackers impersonate legit users/orgs within slack

        - send messages containing malicious links/requests for information

    2. malware

        - can be distributed via files/links shared in channels or DMs

        - users can infect their systems unintentionally, and further spread the malware

    3. data leakage

        - compromised accounts can intentionally or accidentally leak data

        - info can be used for espionage, blackmail, public exposure

    4. integration exploits

        - integration with other services/tools can be exploited

        - poorly secured integrations used to gain access to external systems/data

    5. credential theft

        - through social engineering/phishing

    6. MITM

        - if slack is intercepted over unsecured WiFi, it could be vulnerable to eavesdropping

        - attackers can potentially intercept/read messages

    7. ransomware/extortion

    8. bot-based attacks

    mitigations:

        1. user awareness/education

        2. secure integrations

        3. channel monitoring

        4. strong authentication

        5. use slack over secure, encrypted networks

        6. regular audits

        7. control file sharing


7. Compliance
Can you explain SOC 2? What are the five trust criteria?
What is the difference between Governance, Risk, and Compliance?

# Intermediate Level

These questions require a deeper understanding and some practical experience:

## 1. Encryption and Authentication

What is a three-way handshake?

**Explain how OAuth (used for token-based auth) works.**

    - roles:

        - resource owner: owns data/resources

        - resource server: server hosting user's data

        - client: app requesting access to user's data on resource server

        - authorization server: server that authenticates resource owner + issues access tokens to client

    - tokens:

        - access token: used by client to access user's data on resource server

        - refresh token (optional): used to obtain new access token when current access token expires

    - flow (OAuth2.0):

        1. authorization request

            - client requests authorization from resource owner to access resources

            - request happens via browser redirect (user asked to authorize client at authorization server)

        2. user authorization

            - resource owner grants client permission at authorization server

            - involves user logging in and consenting to grant access to data

        3. authorization grant

            - authorization server provides authorization grant to client

            - grant can be authorization code, implicit grant, resource owner creds, client creds

        4. access token request

            - client requests access token from authorization server by presenting authorization grant + credentials

            - happens behind the scenes, without user interaction

        5. issuing access token

            - authorization server authenticates client, validates authorization grant

            - issues access token (plus optional refresh token) to client

        6. accessing resources

            - client uses access token to request resources from resource server

            - resource server validates access token + serves client's request

    - grant types:

        - authorization code: for apps running on web server; involves redirection to authorization server for user auth

        - implicit: simplified flow used by mobile/web apps where access token is returned immediately without an extra authorization code exchange step

        - resource owner password creds: used by trusted clients, resource owner provides username and password directly to client

        - client creds: used for server-server communication, client acts on own behalf (not for user)

    - security:

        - redirect URIs: must be pre-registered + validated to prevent reflection attacks

        - access token security: transmit securely and stored safely to prevent authorized access

        - consent + transparency: understand what perms are being granted

        - token scope + lifetime: limit access tokens to minimal scopes/durations necessary for task


**Describe the difference between synchronous and asynchronous encryption.**

    - **synchronous (symmetric)**

        - uses same key for encryption + decryption (symmetric key)

        - sender + receiver possess the same key and must keep it secret

        - sender uses symmetric key to encrypt plaintext into ciphertext

        - receiver uses same key to decrypt ciphertext into plaintext

        - common algos include AES, DES, 3DES

        - faster + less resource-intensive than asynchronous

        - suitable for encrypting large amounts of data

        - key distribution problem (how to distribute key to recipient securely)

        - used for encrypting data at rest (disk files) and data in transit (secure VPNs)

    - **asynchronous (asymmetric)**

        - public + private key

        - public key openly shared, private key secret

        - message encrypted with public key can only be decrypted with private key (and vice versa)

        - secure communication even if public key is known

        - common algos include RSA, ECC (elliptic curve crypto), EIGamal

        - slower + more computationally intensive

        - not used for encrypting large volumes of data

        - no key distribution problem

        - can be used for digital signatures to ensure authenticity and non-repudiation

        - used for secure key exchange, digital signatures, encrypting small amounts of data (keys, passwords, messages, etc)

    - **differences**

        - key management

        - speed/efficiency

        - common applications


Describe SSL handshake.

**Should you encrypt all data at rest?**

    - refers to data stored on physical medium (hard drive, SSD, USB, cloud, i.e. not being transferred/processed)

    - encryption: transform into unreadable format using crypto algos

    - **yes**

        - encryption is vital for protecting sensitive data from unauthorized access

        - regulations (like GDPR, HIPAA, PCI-DSS) mandate or strongly recommend encryption

        - adds an additional layer of security

    - **no**

        - can introduce latency + reduced performance

        - managing keys and maintaining encryption protocols can add complexity to operations

        - additional costs

        - not all data is equally sensitive

    - **balanced**

        - classify data based on sensitivity

        - robust key management practices

        - regular audits

        - built-in encryption options in dbs, file systems, cloud services

        - use as part of a broader security strategy (access controls, network security, security training)


## 2. Network Level and Logging

Explain TCP/IP concepts.

How does a router differ from a switch?

What is the difference between HTTPS and SSL?


**How does threat modeling work?**

    - identify, prioritize, address potential security threats

    - simulate attack scenarios, assess vulns in connected systems/apps

    - reduce org's risk exposure by identifying vulns and potential attack vectors

    - threat, vuln, risk

    - process:

        1. define scope

        2. asset identification

        3. identify threats

        4. analyze vulns + prioritize risks

        5. develop + implement countermeasures

        6. monitor + evaluate

    - collab (security, engineering, IT, governance, business, end users)

    - frameworks

        - MITRE ATT&CK (map identified threats to known adversary methods): knowledge base of TTPs

        - DREAD (Damage, Reproducability, Exploitability, Affected Users, Discoverability): risk assessment model, quantitative approach to prioritizing threats

        - STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege): categorizing threats in software systems

        - PASTA: aligns threat modeling with business objectives, across various org contexts

    - benefits

        - enhances awareness, identifies vulns

        - prioritizes risk mitigation, optimizes security controls

        - adapts to evolving threats, improves org resilience


Explain the difference between IPSEC Phase 1 and Phase 2?

How does HTTPS work?

## 3. OWASP Top 10, Pentesting, and/or Web Applications

Explain man-in-the-middle attacks.

Describe what are egghunters and their use in exploit development.

How is padlock icon in browser generated?

## 4. Databases

**How would you secure a Mongo database? Postgres?**

    - **mongoDB**:

        1. enable authentication

            - turn on mongo built-in authentication, use SCRAM-SHA-256 for strong password auth

            - create specific user accounts with least privs necessary for role

        2. configure RBAC

            - define roles, assign them only necessary privs for accessing/modifying data

        3. encrypt data

            - encryption at rest to protect stored data using mongo's native encryption features

            - use TLS/SSL for data in transit to secure client-server comms

        4. network security

            - bind mongoDB to local interface or use firewalls to restrict which clients can connect to db server

            - use VPN/private network for added security

        5. audit/monitor db activity

            - enable mongo's auditing features to track/log access and changes to db

            - regularly monitor logs for unusual/unauth'd activities

        6. regular updates + patches

        7. backup + disaster recovery

        8. avoid exposing mongoDB to internet: always use app-level access or secure APIs

    - **postgresql**:

        - pretty much the same as mongo except `pg_hba.conf` can be configured to control which hosts can connect and how, and parametrized queries should be used to prevent SQLi attacks

    - keep dev, test, prod envs separate


## 5. Tools and Games

Given a sample packet capture - Identify the protocol, the traffic, and the likelihood of malicious intent.

**How would you use CI/CD to improve security?**

    - integrating security

        1. automated security scanning

            - tools like SAST/DAST can identify vulns early in dev process

            - use software composition analysis tools to check for vulns in 3rd party libraries or dependencies

        2. code quality checks

            - implement code quality gates that prevent merging code changes that do not meet predefined security standards

            - use linters/code analyzers to enforce best practices + detect security anti-patterns

        3. secrets management

            - automate process of securing/managing secrets (API keys, passwords, certs)

            - tools like HashiCorp Vault, AWS Secrets Manager, etc can be integrated into CI/CD pipeline

        4. automated compliance checks

            - incorporate tools to check for compliance with standards/regulations

            - use IaC (infra as code) scanning tools to ensure that infrastructure deployments adhere to best practices

        5. container scanning

            - intergrate container scanning tools into CI pipeline to identify vulns within container images

        6. dynamic env testing

            - automatically deploy changes to dynamic testing env where additional security tests can be conducted, included pentesting + runtime analysis

    - continuous delivery/deployment

        1. automated deployment

            - reduce human errors

            - use tools like jenkins, gitlab, github actions

            - ensure deployment process includes steps to verify security of deployment (check for proper configs + runtime env security)

        2. post-deployment monitoring

            - integrate security monitoring tools into prod env to continuously monitor for suspicious activities or vulns

            - implement logging/alerting mechanisms to detect + respond to incidents in real-time

    - security in infra management

        1. IaC

            - merge infra thru code to ensure consistent and repeatable setups

            - perform regular audits on IaC to detect misconfigs

        2. regular updates + patches


## 6. Programming and Code

How would you conduct a security code review?

Given a CVE, walk us through it and how the solution works.


## 7. Compliance

How is ISO27001 different from SOC 2?

What does Zero Trust mean?

What is role-based access control (RBAC) and why is it covered by compliance frameworks?


# Advanced Level

These questions are highly technical and require extensive knowledge and experience:

## 1. Encryption and Authentication

**How do cookies work? How do sessions work?**

    **cookies**:

        - small pieces of data stored on client's browser

        - sent to/from server with each web request, allowing server to maintain state or remember info about user

        - key-value pairs that server instructs client's browser to store

        - when a user visits website, server sends `Set-Cookie` header with response

        - browser automatically attaches these cookies to every subsequent request to the same domain using `Cookie` HTTP header

        - attributes:

            - `Expires/Max-Age`: how long cookie should be stored

            - `Domain`: which domain cookie belongs to

            - `Path`: limits cookie to specific path within domain

            - `Secure`: cookie should only be sent over HTTPS connections

            - `HttpOnly`: prevents javascript access to cookie (mitigates XSS)

            - `SameSite`: controls when cookies are sent with cross-site requests

        - session cookies are temporary + deleted when browser is closed (no expiration time set)

        - persistent cookies remain on device until expiry or deletion

        - vulnerable to theft (via XSS) or interception

        - mitigation through setting `HttpOnly`, `Secure`, `SameSite`

    **sessions**:

        - store data on server-side, linked to unique session ID

        - session ID usually sent to browser as session cookie

        - created upon user login or when user starts interacting with an app that requires state mgmt

        - persists across multiple HTTP requests, ends with user logout or inactivity

        - can include sensitive info like user ID, auth tokens, user prefs

        - data accessible server-side by referencing session ID received from client's cookie

        - security:

            - regenerate session IDs post-auth to prevent session fixation attacks

            - implement session timeouts 

            - store minimal sensitive data

            - secure session data storage + retrieval

    **cookies + sessions**:

        - cookies (with session IDs) and sessions work together to maintain state/user data

        - cookies identify session, sessions store data server-side

        - use HTTPS to secure cookie transmission

        - implement CSRF tokens in conjunction with sessions to prevent CSRF attacks

        - regular audit + validation


**What is a public key infrastructure (PKI) flow and how would I diagram it?**

    - components:

        1. CA (cert authority): issues digital certs, validates requests for digital certs and issues to verified entities

        2. RA (registration authority): verifier for CA, performs prelim verification before CA issues certs

        3. certificate db: stores issued certs and their status (valid, expired, revoked), repo for cert management

        4. certificate store: resides on client and stores trusted CA certs, helps client verify authenticity of received certs

        5. end users: individuals or systems that use/rely on digital certs or secure communication

    - 
**How does HMAC (Hash-based Message Authentication Code) work? Why is HMAC designed in that way?**

    - components

        - involves crypto hash function (like SHA-256) + secret key

        - process combines message with key to produce a unique hash

    - process

        - key + message: key is combined with message; if key is shorter than block size of hash func, it's padded; if key is longer, it's hashed to fit

        - inner + outer hash: combined message + key are first hashed (inner), result is then combined with key again and hashed again (outer)

        - formula: `HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))`

            - `H` is hash function

            - `K'` is modified key

            - `m` is message

            - `opad`, `ipad` are specific padding constants

            - `||` is concatenation

        - result: output is an HMAC value unique to message + key combo; this value is sent along with message

    - HMAC provides authentication (source verification) and integrity (ensuring message wasn't altered)

    - secret key ensures only those with the key can generate/verify an HMAC

    - double hashing protects against length-extension attacks (common in some hash funcs)

    - design makes it computationally infeasible to retrieve original key/message

    - HMAC can be used with any iterative crypto hash func (MD5, SHA-1, SHA-256); allows it to adapt as hash funcs evolve

    - HMAC process is relatively simple -> efficient to compute

    - easy to implement in various envs and programming langs

    - commonly used in API authentication (API requests)

    - data integrity

    - digital signatures 


**How does Kerberos work?**

    - components:

        - client

        - server

        - KDC (key distribution center):

            1. AS (authentication server) - authenticates clients and issues TGTs (tickets granting tickets)

            2. TGS (ticket granting server) - issues service tickets based on TGTs

    - authentication process

        1. initial authentication:

            - client requests access

            - client sends pre-auth request to AS in KDC, including client ID and ID of desired service

        2. TGT issuance

            - AS validates client using information in the db (password)

            - AS issues TGT encrypted with secret key derived from client's password

        3. TGT retrieval by client

            - client receives + decrypts TGT using the password

            - TGT contains session key for further comms + timestamp

        4. request service ticket

            - client sends TGT to TGS with request for specific service

            - client also sends service request including TGT + authenticator, encrypted with session key

        5. service ticket issuance

            - TGS decrypts TGT, retrieves session key, decrypts authenticator

            - TGS issues service ticket, encrypted with service's secret key

        6. access

            - client sends service ticket to server

            - server decrypts ticket with secret key, verifies client's credentials, grants access

        7. session

            - client + server use session key (incl in service ticket) to communicate securely

    - features

        - encrypted tickets

        - limited lifespan of tickets

        - mutual authentication

        - session keys (temporary)

        - time-sensitive

        - single point of failure (KDC)

        - password vulnerabilities


**If you're going to compress and encrypt a file, which do you do first and why?**

    - compress then encrypt

    - efficiency: 

        - compression eliminates redundancy (predictable patterns or repeated content)

        - pre-encryption state means the data maintains its inherent patterns + redundancy

    - impact of encryption:

        - encryption algos transform data into ciphertext, this randomness eliminates redundancy and patterns

        - post-encryption state: data lacks the structure that compression leverages, meaning compressing an encrypted file doesn't reduce its size and may even increase it

    - security: 

        - leakage: compression after encryption can potentially leak information about encrypted data, patterns in compression results can be exploited to glean information about underlying encrypted data

        - uniformity: encryption produces output that is indistinguishable from random data (crucial for security)

    - performance:

        - compressing first is more computationally efficient (compression requires less power compared to encryption)

    - modern formats combine compression and encryption into a single step


**How do I authenticate you and know you sent the message?**

    - mechanisms:

        1. digital signatures

            - asymmetric cryptography

            - sender signs message with private key, receiver uses sender's public key to verify signature

            - if signature is valid, it confirms message was sent by holder of corresponding private key

        2. PKI

            - involves digital certs issued by CAs

            - certs bing public key to entity (individual or org)

            - verification of digital signature with cert confirms sender's identity

        3. hash funcs + HMAC

            - hash func generates fixed-size hash value from message

            - any change in message results in different hash, ensuring integrity

            - HMAC involves secret key + message hash, providing integrity/authentication

        4. TLS/SSL

            - secure internet comms

            - provides auth thru digital certs and encrypts data

    - process

        1. sender encrypts/signs message using private key or shared secret key

        2. message transmitted over network (TLS used to protect message in transit)

        3. recipient uses sender's public key or shared secret key to decrypt/verify message

        4. recipient can check signature using sender's public key

        5. if decryption/verification is successful, sender's identity is confirmed (authentication) and message integrity is confirmed

    - considerations

        - key management

        - cert validity

        - timestamps + nonces: use timestamps/nonces (number/bit string used only once in security protocol) to prevent replay attacks (old messages resent to fake current transaction)


## 2. Network Level and Logging

Draw a network, then expect them to raise an issue and have to figure out where it happened.
Describe the Risk Management Framework process and a project where you successfully implemented 
compliance with RMF.


**How does a packet travel between two hosts connected in the same network?**

    - hosts are connected through a switch or a router operating in switch mode

    - each host has IP address (logical) and MAC address (physical)

    - process:

        1. host A creates data packet, which includes dest IP address (host B)

        2. if host A doesn't have host B's MAC address, it broadcasts ARP request on network

        3. ARP request asks which host owns the IP address of host B

        4. host B responds with MAC address

        5. host A encapsulates packet in ethernet frame

        6. frame includes source MAC and destination MAC

        7. frame sent to network switch

        8. switch uses MAC address table to determine which port associated with host B's MAC
        9. switch forwards frame out through port connected to host B

        10. switch uses MAC -> process is efficient and reduces network traffic

        11. host B receives frame, de-encapsulates it to extract packet, processes data

        12. if using TCP, host B sends ACK back to host A (using the same process)

    - involves data link layer and network layer



**What are the biggest AWS security vulnerabilities?**

    1. misconfigured S3 buckets

        - S3 buckets with improper access controls

        - access policies, bucket policies, ACLs, audit S3 configs

    2. inadequate UAC

        - overly permissive IAM

        - follow least privilege principle, review IAM policies, use IAM roles/conditions

    3. unsecured APIs/endpoints

        - exposing AWS service APIs/endpoints without proper security can lead to unauth access

        - secure API endpoints with API Gateway, implement authentication/authorization, use VPC endpoints

    4. weak encryption

        - failure to encrypt data at rest/in transit

        - use KMS (key management service) and encrypt data in transit (TLS/SSL)

    5. network segmentation

        - insufficient network segmentation

        - use VPC (virtual private cloud) + subnetting to segment networks, implement security groups + NACLs (network access control lists)

    6. unpatched/outdated systems

        - patch/update EC2 instances (use AWS Systems Manager for patch management)

    7. logging

        - use AWS CloudTrail, CloudWatch, Config for logging + monitoring

    8. unmanaged secrets

        - use AWS Secrets Manager or Parameter Store to manage secrets securely

    9. DDoS

        - use AWS Shield and AWS WAF to protect against DDoS

    10. insecure serverless deployments

        - serverless architectures (using AWS Lambda) can be vulnerable if not secured

        - secure function triggers, manage perms correctly, monitor function executions


How do web certificates for HTTPS work?


**Is ARP UDP or TCP?**
    
    - neither

    - ARP operates on layer 2 (link layer)

    - TCP/UDP operate on layer 4 (transport layer)

    - ARP maps a network address to a physical address (IP address -> MAC address)

    - devices maintain an ARP table/cache, storing maps of IP/MAC


**Explain what information is added to a packet at each stop of the 7 layer OSI model.**

    1. physical layer

        - no information added to data

    2. data link layer

        - adds MAC (media access control) addresses to data, creating a frame

        - includes source/dest MAC addresses

    3. network layer

        - adds IP addresses and other routing info, creating a packet

        - includes source/dest IP addresses

    4. transport layer

        - adds TCP/UDP headers

        - TCP: includes source/dest port numbers, sequence and acknowledgement numbers, flags for controlling data flow

        - UDP: includes just port numbers and length field

    5. session layer

        - adds data related to session establishment, management, termination

        - includes session IDs, auth tokens (often implemented in application protocol)

    6. presentation layer

        - handles data encryption, compression, translation

        - might encrypt data before transmission and decrypt upon reception (TLS/SSL)

    7. application layer

        - adds app-specific data

        - varies depending on protocol (HTTP/FTP/SMTP)

        - includes protocol-specific request/response data


**How does an active directory work? Do you know how Single Sign-On works?**

    1. **AD**

        - domain controller (DC): 

            - authenticates/authorizes all users and computers in a windows domain

            - enforces security policies + installs software updates across network

        - data store:

            - AD stores info about objects (users, groups, printers, hosts) in data store

            - data store is hierarchical and follows X.500 standard

        - LDAP:

            - LDAP facilitates communication between clients + servers

        - authentication/authorization:

            - user logs into computer connected to AD -> creds sent to DC

            - DC then authenticated user and provides access to network based on permissions

    2. **SSO**

        - establishes trusted relationship between service provider (app) and ID provider (ID/credential manager)

        - authentication

            - user logs into SSO enabled app -> redirected to ID provider

            - successful authentication -> ID provider sends token (SAML/OAuth) back to service provider (app)

            - token proves user has been authenticated, service provider grants access

        - subsequent logins

            - user doesn't need to re-enter creds for other SSO-enabled apps during session

            - ID provider will provide tokens to any additional apps the user accesses

    3. **AD + SSO**

        - AD serves as ID provider for SSO

        - user logging into workstation -> authenticated to access other apps linked via SSO

        - centralized mgmt: AD + SSO simplifies mgmt of user creds + access, changes made in directory are reflected across network/apps

        - security: convenience means compromising a user's creds could give attacker access to multiple systems (use MFA!)


    4. **cloud**

        - ADaaS: (AWS Directory Service, Azure AD)

        - hybrid envs: on-prem AD extended or synchronized with cloud-based AD (seamless user mgmt + auth across the environments)

        - integration: cloud-based AD can manage users/perms for various cloud resources

        - cloud-based IdP: SSO in cloud involves cloud-based IdP (Okta, OneLogin, AWS Cognito, Azure AD, Google Identity), they manage user IDs and auth across multiple apps

        - SSO protocols: SAML, OAuth, OpenID Connect

        - SSO handles auth tokens/perms once user is auth'd by IdP

        - greater scalability + accessibility

        - due to distributed nature, security/privacy/encryption (MFA) is super important




How do you harden a system? How to you elevate permissions?

**What is traceroute? Explain it in details.**

    - `tracert` is a network diagnostic tool used to determine the path packets take to reach a destination IP

    - how it works:

        1. packet with TTL:

            - traceroute sends out a series of packets to dest IP

            - each set of packets has an incrementally increasing TTL (starting from 1)

            - TTL is a field in the IP packet header, specifies how many hops (routers) the packet can traverse before it's discarded/returned

        2. TTL expiry + ICMP messages

            - each router along the path decrements TTL by 1

            - when TTL reaches 0, router stops forwarding packet and sends back ICMP "time exceeded" message to source

            - ICMP message includes router IP

        3. incrementing TTL values

            - traceroute increments TTL with each set of packets sent

            - this process reveals path, hop by hop

            - with each increase in TTL, packets are designed to expire at next hop in path, causing each router along path to return ICMP message

        4. determining path + transit delays

            - by examining the return time of each ICMP message, traceroute calculates round-trip time (RTT) for each hop

            - this helps diagnose network latency issues and pinpoint where delays occur

        5. completion

            - process continues until packets reach destination or max hops are reached, preventing infinite loops

            - if packet reach dest, dest host returns ICMP "echo reply", signalling end of traceroutes

    - output: each hop, IP address, RTT for each packet sent, hop's hostname

    - uses:

        - network troubleshooting

        - path analysis

        - performance evaluation

    - limitations:

        - firewalls/filters

        - asymmetric routing (return path can be different)

        - limited visibility (no info about switches, load balancers, other network devices)


What is SYN/ACK and how does it work?

You got the memory dump of a potentially compromised system, how are you going to approach its analysis?

How would you detect a DDOS attack?

**How does the kernel know which function to call for the user?**

    1. syscalls:

        - syscalls is the mechanism thru which user-space apps interact with kernel

        - when a user needs to perform an op that requires kernel privs (accessing hardware, file systems), it makes a syscall

        - a specific CPU instruction triggers a switch from user mode to kernel mode (`int` on x86 architectures)

        - this instruction includes an ID for the desired syscall

    2. interrupts

        - CPU instruction triggers an interrupt, control then passed to kernel

        - kernel has an interrupt handler for these syscall interrupts

        - kernel maintains a syscall table (mapping syscall IDs -> corresponding kernel func addresses)

        - interrupt handler uses syscall ID to look up appropriate func address in syscall table

    3. execution

        - user program executes syscall instruction, specifying syscall number

        - CPU switches to kernel mode, syscall interrupt handler in kernel takes control

        - handler looks up syscall table, finds funcaddress and calls it

        - control returned to user-space program (with some return value from syscall)

    4. security

        - kernel validates params passed with syscalls to prevent security breaches

        - kernel checks whether calling process has sufficient privs to perform requested operation


How would you go about reverse-engineering a custom protocol packet?

## 3. OWASP Top 10, Pentesting, and/or Web Applications

**Do you know what XXE is?**

    - XML External Entity

    - attacker exploits XML parsers that process external entity references within xml documents

    - attacker injects malicious xml content that includes references to external entities (can be files on server, or even network calls to external systems)

    - misconfigured/outdated XML parsers allow parsing of external entities

    - apps accept xml input directly from untrusted sources (without proper sanitization/security checks)

    - can lead to unauth'd access to sensitive data

    - DoS

    - SSRF: can be used to make server perform unintended requests to other systems

    - mitigations:

        - disable external entities + DTDs (document type definitions)

        - input validation + sanitization

        - less complex data formats (JSON)

        - patch + update libraries and parsers

        - testing in the SDLC


## 4. Databases

**which db would you recommend to a client for security reasons, and why?**

    - various factors: needs, nature of data, scale of ops, compliance reqs, existing infrastructure

    - oracle:

        - advanced security options like Transparent Data Encryption, Data Redaction, DB Vault, etc.

        - strong access controls, encryption at rest/in transit, robust auditing capabilities

        - best for:
            
            - large enterprises with complex reqs + budget

            - strong compliance adherence (GDPR, HIPAA)

    - MS SQL:

        - provides Always Encrypted feature, Row-Level Security, Dynamic Data Masking

        - strong integration with windows envs + AD

        - best for:

            - businesses heavily integrated into microsoft ecosystem

            - scenarios where windows-based auth + easy integration with other microsoft products are beneficial

    - MySQL + PostgreSQL

        - SSL support, password encryption, user priv management (MySQL)

        - robust access control, column/row-level security, support for MFA + certs (PostgreSQL)

        - best for:

            - open source solutions for small/medium sized businesses

            - postgreSQL has more advanced security features

    - MongoDB

        - field-level encryption, auditing, authentication, authorization

        - TLS/SSL for encryption in transit, and encryption at rest capabilities

        - best for:

            - scenarios requiring NoSQL with flexible schemas (large, unstructured dataset)

            - projects needing scalable, high-perf data storage with robust security

    - Amazon Aurora

        - inherits security measures from AWS, like network isolation (Amazon VPC), encryption at rest (AWS Key Management Service), automated backups

        - best for:
            
            - businesses looking for cloud-native db with seamless scalability + integration with AWS 
            
            - envs where high availability/durability are priorities


**Our DB was stolen/exfiltrated. It was secured with one round of sha256 with a static salt. What do we do now? Are we at risk? What do we change?**

    1. immediate response:

        - containment + assessment: 

            - isolate affected systems (disconnect from network)

            - assess extent of breach (determine which parts of breach were stolen and nature of data involved)

        - notification + legal compliance

            - notify relevant parties

            - review legal obligations under data protection laws (GDPR, HIPAA)

    2. analyze risk

        - SHA256 with static salt:

            - vulnerability: using a static salt means once the salt is known, it can be used to crack all hashed passwords more efficiently

            - risk: moden GPUs can compute hash functions at high speed, making it feasible to crach a large number of hashes

        - data at risk:

            - password reuse: users with recycled passwords across different services can have their accounts compromised

            - sensitive data exposure: can lead to identity theft, fraud, espionage

    3. mitigation + strengthening security

        - password reset + user comms

            - force password resets

            - communicate transparently

        - improve hashing strategy

            - use unique salts: each hash calculation is unique, reducing risk of mass-decryption

            - stronger hash functions: bcrypt, designed for securing passwords (slower, cost factor for added security)

        - overall security

            - regular audits

            - access controls

            - monitor suspicious activity

        - data encryption

            - encrypt sensitive data (at rest) beyond hashing passwords

            - key management

        - IR plan

            - clear plan for future incidents

    4. long term changes

        - security culture + training

            - employee training

            - security awareness

        - security reviews and updates
        
            - stay updated

            - adaptive security posture


## 5. Tools and Games

**If left alone in office with access to a computer, how would you exploit it?**

    1. initial access: 

        - physical (unattended, unlocked, passwords nearby)

        - usb (malicious software, keyloggers, backdoors)

    2. network exploitation

        - network sniffing tools to capture data over network (if network is unsecured)

    3. known vulns

        - outdated software, unpatched systems

        - weak passwords (default passwords, dictionaries)

    4. social engineering

        - phishing attacks against other employees

    5. privilege escalation

        - exploiting user permissions: if logged-in user has admin privs, attacker can install software, access restricted data, create backdoors


**You have a pipeline for Docker images. How would you design everything to ensure the proper security checks?**

    1. dev

        - secure base images

            - official and minimal base images to reduce attack surfaces

            - regularly update base images to include latest security patches

        - code analysis

            - static code analysis tools to detect security vulnerabilities and bad practices in app code

    2. build

        - automated vuln scanning

            - vuln scanning tools (Clair/Anchore/Trivy) in CI/CD pipeline to automatically scan docker images

            - scan both OS packages and app dependencies

        - image hardening

            - remove unnecessary tools, files, privs from images

            - follow least privilege principle for app/user perms within container

        - secrets management

            - avoid hardcoding secrets in images

            - use secrets management tools (HashiCorp Vault, AWS Secrets Manager, Docker Secrets)

    3. ci/cd pipeline

        - pipeline security

            - RBAC to determine who can modify pipeline and deploy images

            - sign + verify images using Docker Content Trust

        - automated testing

            - automated security testing and config checks in ci/cd process

            - perform DAST and integration testing to detect runtime vulns and config issues

    4. deployment

        - runtime security

            - container orchestration tools (Kubernetes) with security policies (Pod Security Policies) to manage container deployments securely

            - implement network segmentation + firewall rules to control traffic to/from containers

        - monitoring + logging

            - monitor container runtime envs for anomalous activities (Falco, Sysdig)

            - comprehensive logging of container activities for future audits + investigations

    5. continuous monitoring + updating

        - regular scanning

            - continuously scan deployed containers/host envs for vulns

            - regularly update containers/hosts with latest security patches

        - IR plan

            - develop/maintain an IR plan specific to containerized envs

            - conduct regular security training/drills for team

    6. documentation + compliance

        - document best practices

        - compliance checks


**How would you create a secret storage system?**

    - define purpose + required security level

    - assess risk + compliance requirements (risks, threats, GDPR, HIPAA)

    - encryption: AES-256 to encrypt data at rest, encrypt individual files as well as entire storage

    - access control: MFA, user roles/permissions

    - secure transmission: encryption during transit (TLS/SSL)

    - integrity: hash functions to verify data has not been tampered with

    - backup/redundancy: regular backups, RAID configurations to protect against data loss

    - physical security: locks, secure location

    - regular audits/monitoring

    - updates + patch management

    - user education

    - contingency/disaster recovery plan


**How would you harden your work laptop if you needed it at Defcon?**

    - OS hardening: update/patch, remove unnecessary services/software, use secure OS

    - network: firewall, VPN, avoid public wifi

    - UAC: strong auth (strong passwords, MFA), least privilege principle (avoid admin account), guest account (non-admin guest account)

    - physical: disk encryption (bitlocker/filevault), secure boot in BIOS (prevent unauth'd bootable systems), physical lock for laptop 

    - data: backups, data encryption (encrypted containers like veracrypt)

    - endpoint: AV/AM, IDS

    - browser: uldated browser with extensions (uBlock, HTTPS Everywhere), disable unnecessary plugins

    - misc: disable bluetooth/NFC, vigilance (phishing, social engineering, unknown USB/peripherals)


**If you had to set up supply chain attack prevention, how would you do that?**


## 6. Programming and Code

**Code review a project and look for the vulnerability.**

   https://github.com/dub-flow/appsec-challenges/tree/main

- If I hand you a repo of source code to security audit what’s the first few things you would do?


**Can I write a tool that would search our Github repos for secrets, keys, etc.? AWS?**

    **github**:

        1. define search criteria (API keys, db creds, ssh keys, private tokens)

        2. API integration (personal access token)

        3. scanning logic (clone repos, scan them, regex/pattern matching to identify potential secrets)

        4. false positives (differentiate between real secrets and false positives, using allowlists or heuristics)

        5. notification (only the relevant stakeholders, maintain logs/reports)

        6. continuous scanning (run periodically or trigger when push/pull)

        ```python

        import requests

        # Constants and configurations
        GITHUB_API = "https://api.github.com"
        TOKEN = "your_personal_access_token"
        HEADERS = {"Authorization": f"token {TOKEN}"}
        ORG_NAME = "your_org_name"

        # Regex patterns for secrets
        SECRET_PATTERNS = ["regex_for_api_key", "regex_for_ssh_key", ...]

        def get_repos():
            """Get a list of repositories from GitHub"""
            response = requests.get(f"{GITHUB_API}/orgs/{ORG_NAME}/repos", headers=HEADERS)
            return response.json()  # Parse and return the list of repositories

        def scan_repo(repo_name):
            """Scan a single repository for secrets"""
            # Logic to clone or access repo content
            # For each file in the repo, search for patterns that match secrets
            # This can be done using regex and scanning through file content
            pass

        def main():
            repos = get_repos()
            for repo in repos:
                scan_repo(repo['name'])

        if __name__ == "__main__":
            main()
        ```
        
    **AWS**

        1. AWS API/SDK: authenticate using IAM roles

        2. scanning AWS: S3 buckets, EC2 instances, RDS dbs, CloudFormation templates, Lambda functions

        3. env config: check for misconfigs, such as open S3 buckets or overly permissive IAM policies

        4. secrets manager/param store: check if secrets manager/param store is being properly used for 
        storing secrets (instead of hardcoding in configurations)

        5. integration with cloudtrail: use cloudtrail logs to monitor for unusual access patterns

    considerations:

        - rate limiting + API quotas

        - secure tool

        - regular updates/maint

        - user training



**Tell me about a repetitive task at work that you automated away.**

- look at some tools on github or my tools

**How would you analyze a suspicious email link?**

    - visual inspection

    - hover to preview URL

    - link scanners (VirusTotal, URLScan, URLVoid, Transparency Report)

    - unshorten URL (unshorten.it) to reveal destination

    - source code of email (look for javascript/embedded scripts)

    - open link in sandbox

    - DNS checks (lookup)

    - IP blacklists

    - inspect email headers (determine source)

    - report


## 7. Compliance

**What is the NIST framework and why is it influential?**

    - core: Identify, Protect, Detect, Respond, Recover

    - implementation: describes degree to which cybersecurity risk management practices exhibit 
    characteristics defined in framework (Partial, Risk-Informed, Repeatable, Adaptive)

    - profiles: used to plan cybersecurity improvements and assess impact of improvements

    - why it's influential:

        1. flexibility + adaptability

        2. risk-based approach

        3. common language (systematic methodology)

        4. compliance + industry standard

        5. global recognition

        6. continuous improvement

    - uses:

        - assessment

        - risk management

        - vendor management
