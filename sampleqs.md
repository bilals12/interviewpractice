# Linux

## easy

1. what command would you use to view the contents of a directory?

- use the `ls` command. 

2. how do you check the permissions of a file?

- `ls -l <filename>`

3. how do you create a new user?

- `useradd <username>`

4. what is the purpose of the `/etc/passwd` (or `/etc/shadow`) file?

- `/etc/passwd` stores user account info (username, UID, GID, home directory, shell)

- `/etc/shadow` contains hashed password data (available to privileged users)

5. how can you redirect output from a command to a file?

- `> filename`, like `ls > file.txt` will direct the output of `ls` into `file.txt`.

6. what does the `chmod` command do?

- specifies who can read, write, or execute the file/directory.

## medium

1. how would you display all running processes in linux?

- `ps aux`

2. how would you recursively search for a specific string within files in a directory? describe how to use `grep` to search for patterns.

- `grep -r "<string pattern>" /path/to/dir`

- search thru all files in directory and its subdirectories + displays files where pattern is found

3. how can you find and terminate a process?

- `ps` or `pgrep`, like `pgrep firefox`. this finds the PID of firefox

- `kill <PID>` to kill process, or `kill -9 <PID>` to force-kill

4. what is a `cron` job and how can you schedule one?

- scheduled task that runs at specified intervals

- edit crontab file using `crontab -e`, then add line specifying wheb task should run and command to execute, using the format "min, hr, day of month, month, day of week, command". 

- `0 5 * * * /script.sh` schedules script to run daily @ 5am

5. explain `iptables` (or `ipset`).

- `iptables` used to configure linux kernel's netfilter firewall. it can set up, maintain, and inspect tables of IP packet filter rules in the kernel

- you can define rules for how to handle incoming/outgoing traffic based on criteria like source/dest IP address, port, protocol

- `ipset` works with `iptables` to manage/match in large volumes

## hard

1. how can you set up SSH key-based authentication?

- generate SSH key pair on client using `ssh-keygen`

- transfer public key to server using `ssh-copy-id user@server`

- ensure server's configuration permits key-based authentication (`/etc/ssh/sshd_config`, look for `PubkeyAuthentication` option and make sure it's set to `yes`. also confirm `AuthorizedKeysFile` line points to correct location of file, usually at `.ssh/authorized_keys`).

- log in using `ssh user@server`

2. describe the process to change kernel parameters in linux.

- use `sysctl` for runtime config or modify `/etc/sysctl.conf` for persistent changes

- temporary change: `sudo sysctl -w parameter=value`

- persistent change: add `parameter=value` to `/etc/sysctl.conf`, apply changes with `sudo sysctl -p` (requires root)

3. how can you recover a system from a lost root password?

- restart system and access GRUB (bootloader menu)

- edit boot params for kernel, adding `init=/bin/bash` (or `rw init=/sysroot/bin/sh` for SELinux). this boots to single-user mode (or root shell)

- remount root filesystem as r/w using `mount -o remount,rw /`

- use `passwd` to change root password, then reboot

4. how can you configure a linux server as a router?

- enable IP forwarding by setting `net.ipv4.ip_forward=1` in `/etc/sysctl.conf` and apply using `sysctl -p`

- configure `iptables` to manage NAT rules, allowing server to forward between interfaces

- this means defining `iptables` rules to mask outbound traffic, making devices behind router appear as if they're using one outgoing IP address.

5. explain the differences between hard and soft links. how would you create them?

- hard links: additional directory entries for a file, sharing same inode number (point to same file content on disk). cannot reference directories.

- soft links (aka symlinks): pointers to file names, acting as shortcuts and can span across file systems. can reference directories.

- create hard link: `ln file1 link1`

- create soft link: `ls -s target link`

6. how would you optimize a linux server for performance?

- adjust `/etc/sysctl.conf` for network/file system performance

- lower swappiness value to reduce disk swapping

- use tools like `iostat` to monitor disk usage

- disable unnecessary services (free up storage)

- optimize TCP/IP settings

- monitor with tools like `top`, `htop`, `vmstat`

- keep updated

# cloud app management

## easy

1. what are the key benefits of cloud computing for app management?

- scalability: easy adjustment of resources to meet demand

- cost efficiency: reducing need for upfront infrastructure investment

- high availability/disaster recovery

- flexibility/agility: quick deployment and updates

- enhanced security

- access to advanced technology (AI/ML)

2. name some advantages of using cloud services over traditional on-prem data centers.

- same as above

3. how do you scale an application in the cloud?

- automatically adjusted by cloud based on demand

- vertically: add more power to existing instances (CPU/RAM)

- horizontally: increase number of instances

- load balancers distribute traffic across instances

4. what is a CDN? why is it used?

- servers that deliver content to users based on geolocation, origin, content delivery server

- reduces latency, speeds up content load times, handles large volumes of traffic efficiently

- also used for protection against large-scale DDoS 

5. compare IaaS, PaaS, SaaS

- IaaS: virtualized computing resources (VMs, storage)

- PaaS: framework for devs to build and create custom apps (manages infrastructure while devs can focus on software)

- SaaS: software on subscription basis

## medium

1. how do you implement disaster recovery in cloud environments?

- identify critical workloads and data that needs protection

- replicate assets across multiple regions/availability zones

- cloud-based backup solutions for data redundancy

- failover mechanisms to switch operations in case of outage

- test plan to make sure it meets RTO (recovery time objectives) and RPO (recovery point objectives)

2. describe a strategy for multi-cloud management.

- centralize visibility and control

- tools that support multi-cloud envs, standardize ops and governance across clouds, consistent security/compliance, optimizing costs

3. how would you secure data in the cloud?

- implement encryption (for data at rest and in transit)

- strong access controls + identity management

- update + patch services and apps

- monitor + log unauthorized access or anomalies

- secure configs (compliance)

- cloud-native security features

- review + audit

4. explain the process of migrating an on-prem app to the cloud.

- choose right cloud provider/service model

- consider data transfer and security needs

- execute migration in phases

- optimize app for cloud env

- minimize downtime

## hard

1. how would you architect a highly available and scalable app deployment in AWS or Azure?

- use EC2 (AWS) or Azure VMs for compute

- use S3 (AWS) or Blob Storage (Azure) for data

- use Auto Scaling (AWS) or VM Scale Sets to adjust resources

- implement load balancers for traffic distribution and Availability Zones for fault tolerance

- use RDS (AWS) or Azure SQL for managed database services

- integrate CDN for global content delivery

- employ monitoring tools for performance insights, automate deployments (using CI/CD pipelines)

2. discuss the challenges of managing stateful applications in the cloud.

- ensuring data persistence across sessions/deployments

- scaling stateful components without data loss/inconsistency

- handling session state across multiple instances

- migrating stateful apps without downtime

- solutions: persistent storage, distributed data stores, managing deployment strategies

3. how do you ensure compliance across different cloud environments?

- unified compliance framework

- utilize cloud management and security tools

- understand compliance offerings

4. describe a cloud architecture you designed for high availability.

5. what are container orchestration tools, and how do they assist in cloud app management?

- manage deployment, scaling, operation of containerized apps across clusters of hosts

- automate container provisioning, networking, load balancing, security

- examples: Kubernetes, Apache Mesos, Docker Swarm

# data security/vulnerability testing

## easy

1. what's the difference between a vulnerability scan and a penetration test?

- vulnerability scan: identifies known vulns, provides reports, automated and broad

- penetration test: simulation of cyber attack, identifies and exploits vulns, manual/targeted

2. what's the difference between symmetric and asymmetric encryption?

- symmetric: same key for encryption/decryption, fast, efficient for large volumes

- asymmetric: secure communication (public + private keys), computationally complex

3. what's a security group in a cloud env?

- virtual firewall that controls inbound/outbound traffic for cloud resources (like VMs)

- defines set of rules that specify allowed and denied traffic

4. how do you ensure data is securely deleted?

- cryptographic wiping: encrypt data before deletion

- physical destruction of storage

- tools that overwrite data multiple times with patterns/random data

5. what are the basic principles of a secure password policy?

- minimum length, mix of upper, lowercase and alphanumeric/special chars, regular changes, no recycling, MFA

## medium

1. how do you stay updated with the latest vulnerabilities and patches?

- automated vendor advisory program (SLACKER)

2. explain XSS and how to prevent it.

- injection of malicious scripts into pages viewed by users

- validate/sanitize user inputs (escape special characters), CSP headers (restrict sources of executable scripts)

- use frameworks that automatically XSS by design

3. describe SQLi and how to mitigate it.

- interfere with queries an app makes to the db to get access to the db

- use prepared statements (parametrized queries: ensure input is treated as data, not code), object-relational mapping libraries (abstract db interactions), validate/sanitize inputs, update/patch

- limit permissions (necessary access rights)

4. how would you conduct a vulnerability assessment?

- define scope: which systems and networks?

- automated scanning tools

- identify + prioritize vulns based on severity/impact

- remediate by applying patches, configuring settings, security controls

- document

5. what is the significance of using HTTPS over HTTP?

- HTTPS uses TLS/SSL for secure communication

## hard

1. discuss the process of handling a data breach.

- identify and contain breach

- identify compromised data/individuals

- notify stakeholders/regulatory bodies (as required by law)

- investigate breach's cause

- secure (patching)

2. how do you perform a threat model for a new software application?

- identify all components, data flows, entry points

- define potential threats using frameworks (STRIDE, MITRE)

- assess risks based on likelihood/impact

- devise mitigation strategies for highest priority risks

- document

3. descibe how to secure a database from injection attacks.

4. explain how to implement E2E encryption in a messaging app.

- use asymmetric encryption (each user has public/private key pair)

- message encrypted with recipient's public key and can only be decrypted by private key

- use signal

# scripting/automation

## easy

1. what scripting languages are you most comfortable with, and why?

2. what's the difference between a script and a program?

3. how can `cron` jobs be used for automation?

4. what is an example of a task you might use a bash script automation for?

5. how do you automate tasks in Windows?

## medium

1. give an example of a task you automated and its impact.

2. how can you automate software deployment?

3. how can you use Python for automation?

4. what tools do you use for infrastructure as code?

- terraform: define cloud resources in config files that can be versioned/reused

- ansible: config management, automates provisioning/deployment of apps and systems

- AWS CloudFormation/Azure Resource Manager: model and set up resources using templates specific to their cloud platforms

- Puppet/Chef: automate deployment/management of infrastructure code across various envs

5. how can you use APIs for automation purposes?

- scripting API calls, streamline workflows, reduce errors, increase efficiency in CI/CD

## hard

1. how would you automate the deployment of a multi-tier application across several environments?

2. describe a complex automation workflow you've implemented.

3. how do you manage error handling in automated scripts?

- try-catch blocks

- log errors for debugging/audit

- conditional statements to check for specific error conditions

- exit codes (success/failure of execution)

- powershell: `Try`, `Catch`, `Finally`

- bash: `set -e` (exits on error)

4. how can you automate network config changes?

- Ansible, Terraform, Puppet: manage/provision network devices programmatically

- define network configs in code, version control the config files, use the tools to apply configs consistently

5. how would you automate security patch deployment across multiple servers?

- same tools as above

- first test patches in staging, then define patch deployment in code

- schedule patch deployment during low-traffic periods

- implement rollback in case of error

# systems design/administration

## easy

1. what are some best practices for maintaining a secure and efficient server environment?

2. what is the role of a DHCP server?

- automatically assigns IP addresses (and other params) to devices on network

- simplifies network admin by eliminating need for manual IP address configs

- supports automatic reassignment of IP addresses to device

- manages IP address allocation to prevent conflicts

3. explain the purpose of DNS in system administration.

- translates domain names to IP addresses

- also manage mail servers for a domain

- manages internal servers

4. what does a load balancer do?

- distributes incoming network traffic across multiple servers to ensure no single server becomes overwhelmed

- optimizes resource use, maximizes throughput, reduces response time, ensures fault tolerance, reroutes traffic in case of server failure

5. how do you monitor system performance?

- system resources (CPU, memory, I/O): `top`, `htop`, `vmstat`, `iostat`

- performance data: `nmon`, `sar`

- GUI: Grafana, Nagios, Prometheus

## medium

1. how would you design a backup and disaster recovery plan for a company's IT infrastructure.

2. how do you set up a secure web server?

3. describe the steps to harden an OS.

4. how do you automate system backups?

5. discuss strategies for managing server updates.

## hard

1. how would you approach the migration of an on-prem infrastructure to the cloud?

2. how do you design a fault-tolerant system?

3. describe the process of migrating from a monolithic architecture to microservices (and the benefits, if any).

4. how would you implement a zero-trust architecture?

5. what considerations are involved in database clustering for high availability?

# virtualization

## easy

1. what is virtualization, and what are the benefits?

2. what's the difference between virtualization and containerization?

- virtualization: create virtual instances of physical hardware to run multiple operating systems

- containerization: app code, configs, dependencies all encapsulated into a single object that runs consistently across any environment

- VMs are fully isolated with their own OS

- containers share host's kernel but isolate app process

- containers are lighter and more efficient than VMs (quicker start times, less overhead)

3. what are the benefits of using VMs?

- strong isolation (different OSs can run on same hardware)

- enhanced security

- easy backup, replication, migration

- flexibility

- distributes hardware's compute among several environments

4. how does hypervisor software work?

- abstracts hardware (CPU, memory, storage) and distributes across VMs

- operates at a layer above physical hardware and below VMs (enables multiple OS to share a single hardware host)

- 2 types: bare metal (runs directly on host hardware) and hosted (runs on conventional OS as an app)

5. what are containers? how are they used?

- lightweight executable units (package of app code, libraries, dependencies in single object)

- share host's kernel but run in isolated user spaces

- ensure apps run quickly and reliably across different envs

- more efficient use of resources

- facilitate CI/CD by allowing devs to create/deploy/scale apps more easily and consistently

## medium

1. how do you monitor and manage VM performance?

2. how do you manage VM storage effectively?

3. explain the process of virtual network configuration.

4. what's the role of orchestration in managing virtualized environments?

5. how can virtualization contribute to disaster recovery planning?

## hard

1. describe your experience with managing large-scale virtualized envs.

2. describe a scenario where container orchestration would be necessary.

3. how do you ensure high availability in a virtualized env?

4. what are the security implications of virtualiztion?

5. how can you optimize performance in a virtualized infrastructure.