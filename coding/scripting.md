Problem 1: Log Analysis Script
Description: Write a script in Python to analyze a log file and extract specific information. The script should be able to count the occurrences of each unique IP address in the log file and display the top N IP addresses with the highest number of requests.

```python
from collections import Counter
import sys

def analyze_log(file_path, top_n):
	try:
		with open(file_path, 'r') as file:
			# extract IP addr from each line
			ip_addresses = [line.split()[0] for line in file if line.strip()]

			# count
			ip_count = Counter(ip_addresses)

			# get top N
			top_ips = ip_counts.most_common(top_n)

			print(f"top {top_n} IP addresses with highest number of reqs:")
			for ip, count in top_ips:
				print(f"{ip}: {count} requests")

	except FileNotFoundError:
		print("error: log file not found")

	except Exception as e:
		print(f"unexpected error occurred: {e}")

if __name__ == "__main__":
	if len(sys.argv) != 3:
		print("usage: python analyze_log.py <path to log file> <top_n>")

	else:
		file_path = sys.argv[1]
		top_n = int(sys.argv[2])
		analyze_log(file_path, top_n)
```

Problem 2: File Backup Script
Description: Develop a shell script that automates the backup process of specific directories to a designated backup location. The script should create incremental backups, handle error checking, and provide logs for each backup operation

`rsync` only copies the changes

```bash
#!/bin/bash

# define source + backup dirs
SOURCE_DIR="/path/to/source"
BACKUP_DIR="/path/to/backup"

# define log file location
LOG_FILE="/path/to/backup/log_$(date +%Y-%m-%d_%H-%M-%S).log"

# start backup
echo "starting backup..."
echo "backup started at $(date)" >> "$LOG_FILE"

# perform backup using rsync
rsync -av --delete "$SOURCE_DIR" "$BACKUP_DIR" >> "$LOG_FILE" 2>&1

# check status of last executed command
if [ $? -eq 0 ]; then
	echo "backup completed successfully at $(date)" >> "$LOG_FILE"
	echo "backup operation completed successfully"
else
	echo "error occurred during backup operation. check log file for details" >> "$LOG_FILE"
	echo "backup operation failed"
fi
```

Problem 3: System Monitoring Script
Description: Create a script in Bash or Python that monitors system resources (CPU, memory, disk usage) and sends alerts if any resource exceeds a predefined threshold. The script should run as a background process and continuously monitor system metrics.

use `psutil`

```python
import psutil
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# thresholds for resources (in %)
CPU_THRESHOLD = 80
MEMORY_THRESHOLD = 80
DISK_THRESHOLD = 80

# email notifs
def send_email(subject, message, to_email):
	smtp_server = "smtp.gmail.com"
	smtp_port = 587 # TLS
	from_email = "bilal.s12@protonmail.com"
	password = "password"

	# setup MIME
	mime_message = MIMEMultipart()
	mime_message["From"] = from_email
	mime_message["To"] = to_email
	mime_message["Subject"] = subject
	mime_message.attach(MIMEText(message, "plain"))

	try:
		server = smtplib.SMTP(smtp_server, smtp_port)
		server.starttls()
		server.login(from_email, password)
		text = mime_message.as_string()
		server.sendmail(from_email, to_email, text)
		server.quit()
		print("alert email sent successfully")
	except Exception as e:
		print(f"failed to send email. error: {e}")

# CPU usage
def check_cpu_usage(threshold, to_email):
	cpu_usage = psutil.cpu_percent()
	if cpu_usage > threshold:
		message = f"WARNING: CPU usage is above {threshold}%: {cpu_usage}%"
		print(message)
		send_email("CPU Usage Alert", message, to_email)

# memory usage
def check_memory_usage(threshold, to_email):
	memory = psutil.virtual_memory()
	memory_usage = memory.percent
	if memory_usage > threshold:
		message = f"WARNING: memory usage is above {threshold}%: {memory_usage}%"
		print(message)
		send_email("Memory Usage Alert", message, to_email)

# disk usage
def check_disk_usage(threshold):
	disk = psutil.disk_usage('/')
	disk_usage = disk.percent
	if disk_usage > threshold:
		message = f"WARNING: disk usage is above {threshold}%: {disk_usage}%"
		print(message)
		send_email("Disk Usage Alert", message, to_email)

# monitor
def monitor_system(interval, cpu_threshold, memory_threshold, disk_threshold, to_email):
	while True:
		check_cpu_usage(cpu_threshold, to_email)
		check_memory_usage(memory_threshold, to_email)
		check_disk_usage(disk_threshold, to_email)
		time.sleep(interval)

if __name__ == "__main__":
	alert_email = "alert@example.com" 
	monitor_system(60, CPU_THRESHOLD, MEMORY_THRESHOLD, DISK_THRESHOLD, alert_email)
```

start as background process

```sh
nohup python system_monitor.py &
```

Problem 4: Data Processing Script
Description: Write a Python script that reads data from a CSV file, performs data manipulation (e.g., filtering, sorting, aggregation), and outputs the processed data to a new CSV file. The script should be flexible to handle different types of data processing tasks.

```python
import pandas as pd

def process_csv(input_file, output_file, process_type):
	# read CSV
	df = pd.read_csv(input_file)

	# perform data manipulation based on process_type arg
	if process_type == "filter":
		# filter rows where ColumnA > 50
		df = df[df['ColumnA'] > 50]
	elif process_type == "sort":
		# sort by ColumnB
		df = df.sort_values(by='ColumnB')
	elif process_type == "aggregate":
		# aggr. data by ColumnC, summing ColumnD
		df = df.groupby('ColumnC')['ColumnD'].sum().reset_index()
	else:
		print("invalid process type")
		return

	# save to new CSV file
	df.to_csv(output_file, index=False)
	print(f"data processed + saved to {output_file}")

# example
input_file = 'input.csv'
output_file = 'processed.csv'
process_type = 'filter'
process_csv(input_file, output_file, process_type)
```

Problem 5: Automated Deployment Script
Description: Develop a script using Ansible or similar tools to automate the deployment of a web application to multiple servers. The script should handle tasks such as copying files, configuring services, and restarting servers as needed.

1. define inventory

in `hosts.ini`, enter servers to deploy to

```ini
[webservers]
192.168.1.10
192.168.1.20
```

2. create playbook

in `deploy_app.yml`, define deployment tasks

```yaml
---

- name: deploy web app
hosts: webservers
become: yes # use sudo

tasks:
	- name: copy web app files
	ansible.builtin.copy:
		src: /path/to/local/app
		dest: /var/www/html/webapp
		owner: www-data
		group: www-data
		mode: '0644'
	
	- name: install Nginx
	ansible.builtin.apt:
		name: nginx
		state: present

	- name: configure nginx for web webapp
	ansible.builtin.template:
		src: /path/to/nginx.conf.j2
		dest: /etc/nginx/sites-available/webapp.conf
	notify: restart nginx

	- name: enable nginx site config
	ansible.builtin.file:
		src: /etc/nginx/sites-available/webapp.conf
		dest: /etc/nginx/sites-available/webapp.conf
		state: link

handlers:
	- name: restart nginx
	ansible.builtin.service:
		name: nginx
		state: restarted


```

3. run playbook

```bash
ansible-playbook -i hosts.ini deploy_app.yml
```

Problem 6: Network Configuration Script
Description: Write a script in Python or PowerShell that automates the configuration of network settings on multiple devices. The script should be able to set IP addresses, subnet masks, gateway addresses, and DNS servers on routers or switches.

connect to devices via SSH and apply configs (IP addresses, subnet masks, gateway addresses, DNS servers)

1. define device info

```python
devices = [
{
	'device_type': 'cisco_ios',
	'ip': '192.168.1.1',
	'username': 'admin',
	'password': 'adminpassword',
	'secret': 'enablepassword',
	'config': [
	'interface GigabitEthernet0/1',
	'ip address 192.168.1.2 255.255.255.0',
	'no shutdown',
	'exit',
	'ip default-gateway 192.168.1.1',
	'ip name-server 8.8.8.8',
	]
},
]
```

2. create script

connect to each device in list, enter config mode, apply settings, exit

```python
from netmiko import ConnectHandler

def configure_device(device):
	try:
		# connect
		with ConnectHandler(**device) as conn:
			if 'secret' in device:
				conn.enable() # enter enable mode
			# send config commands
			output = conn.send_config_set(device['config'])
			print(f"config output for {device['ip']}:\n{output}")

			# save config
			conn.save_config()

	except Exception as e:
		print(f"failed to configure device {device['ip']}: {e}")

if __name__ == "__main__":
	for device in devices:
		configure_device(device)
```

Problem 7: Database Backup Script
Description: Create a shell script that automates the backup of a MySQL or PostgreSQL database. The script should dump the database contents to a file, compress it, and store it in a specified backup directory with proper error handling.

mysql:

```bash
#!/bin/bash

# db creds
DB_NAME="db name"
DB_USER="db user"
DB_PASSWORD="db password"

# backup dir
BACKUP_DIR="/path/to/backup"

# backup file name format
DATE=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_FILE_NAME="backup_$DB_NAME_$DATE.sql.gz"

# log file
LOG_FILE="$BACKUP_DIR/backup_log.txt"

# start backup
echo "starting backup for db $DB_NAME at $DATE" >> "$LOG_FILE"

# dump + compress db
mysqldump --user=$DB_USER --password=$DB_PASSWORD $DB_NAME | gzip > "$BACKUP_DIR/$BACKUP_FILE_NAME"

# check status of dump
if [ $? -eq 0 ]; then
	echo "backup completed successfully at $(date)" >> "$LOG_FILE"
else
	echo "error occurred during backup" >> "$LOG_FILE"
```

for postgresql, replace `mysqldump` with `pg_dump`

```bash
pg_dump -U $DB_USER -W $DB_PASSWORD $DB_NAME | gzip > "$BACKUP_DIR/$BACKUP_FILE_NAME"
```

Problem 8: Website Monitoring Script
Description: Develop a Python script that periodically checks the availability and response time of a list of websites. The script should send alerts if any website is down or responding slowly, providing detailed information about the issue.

```python
import time
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

websites = [
"https://example.com",
"https://google.com"
]

response_time_threshold = 2 #seconds

# alert
def send_email(subject, message, to_email):
	smtp_server = "smtp.gmail.com"
	smtp_port = 587
	from_email = "bilal.s12@protonmail.com"
	password = "password"

	mime_message = MIMEMultipart()
	mime_message["From"] = from_email
	mime_message["To"] = to_email
	mime_message["Subject"] = subject
	mime_message.attach(MIMEText(message, "plain"))

	try:
		server = smtplib.SMTP(smtp_server, smtp_port)
		server.starttls()
		server.login(from_email, password)
		server.sendmail(from_email, password)
		server.quit()
		print("email alert sent!")

	except Exception as e:
		print(f"failed to send email alert. error {e}")

# monitor
def check_website(url):
	try:
		response = requests.get(url, timeout=10)
		response_time = response.elapsed.total_seconds()
		if response.status_code != 200:
			send_email("website down!", f"website {url} is down. status code: {response.status_code}", "alert_email@example.com")
		elif response_time > response_time_threshold:
			send_email("website is responding slowly", f"website {url} is responding slowly. response time: {response_time} seconds", "alert_email@example.com")
		else:
			print(f"website {url} is up. response time: {response_time} seconds")
	except requests.RequestException as e:
		send_email("website down alert", f"website {url} could not be reached! error: {e}", "alert_email@example.com")

# periodic check
if __name__ == "__main__":
	alert_email = "alert_email@example.com"
	while True:
		for website in websites:
			check_website(website)
		time.sleep(60 * 10) # every 10 mins
```

Problem 9: Cleanup Script in Bash
Description: Write a Bash script to clean up old files in a directory. The script should accept two parameters: the directory path and the file age (in days). It should then find and delete all files in the specified directory that are older than the specified age. Ensure the script logs deleted files and handles errors gracefully.

```bash
#!/bin/bash

# check correct num of args
if [ "$#" -ne 2 ]; then
	echo "usage: $0 <dir_path> <file_age_days>"
	exit 1
fi

DIRECTORY_PATH=$1
FILE_AGE=$2
LOG_FILE="cleanup_log_$(date +%Y-%m-%d_%H-%M-%S).txt"

# check if dir exists
if [ ! -d "$DIRECTORY_PATH" ]; then
	echo "error: dir doesn't exist: $DIRECTORY_PATH"
	exit 1
fi

# find + delete files older than spec age
find "$DIRECTORY_PATH" -type f -mtime +$FILE_AGE -print -delete > "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
	echo "cleanup successful. see $LOG_FILE for details"
else
	echo "error occurred during cleanup. check $LOG_FILE for details"
	exit 1
fi
```

Problem 10: Server Health Check Script in PowerShell
Description: Develop a PowerShell script that performs a health check on a list of servers. The script should ping each server and check for available disk space and CPU usage. If a server does not respond to the ping or if any server's disk space or CPU usage exceeds a predefined threshold, the script should send an alert (for the purpose of this exercise, simply outputting to the console is sufficient).

```powershell
$servers = @("Server1", "Server2") # list servers
$diskSpaceThresholdPercent = 80
$cpuUsageThresholdPercent = 80

foreach ($server in $servers) {
	# check if server responds to ping
	$pingResult = Test-Connection -ComputerName $server -Count 2 -Quiet

	if (-not $pingResult) {
		# server not responding
		Write-Output "alert: $server not responding to ping"
	} else {
		# check disk space
		$diskSpace = Get-WmiObject -ComputerName $server Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object { ($_.FreeSpace / $_.Size) * 100 } | Where-Object { $_ -lt (100 - $diskSpaceThreshold) }

		if ($diskSpace) {
			Write-Output "alert: $server has low disk space"
		}

		# check CPU usage
		$cpuUsage = Get-Counter -ComputerName $server "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue
		if ($cpuUsage.CounterSamples.CookedValue -gt $cpuUsageThreshold) {
			Write-Output "alert: $server CPU usage is high"
		}
	}
}
```

