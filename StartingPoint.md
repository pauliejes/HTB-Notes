# Hack The Box CTF Challenge Guides

## ***Fawn Box***

### Introduction
- Explore common FTP misconfigurations, focusing on the exploitation of anonymous access which is frequently not secured properly.

### Enumeration
- Utilize Nmap to scan for FTP services. Use the command `nmap -p 21 -sV [target IP]` to look specifically for port 21 and check if the server permits anonymous login, a significant security flaw allowing unauthorized data access.

### Foothold
- Log in anonymously to the FTP server using a command like `ftp [target IP]`, then enter `anonymous` as the user and press enter when prompted for a password. Navigate the FTP directories using `ls` and `cd` commands. Search for sensitive files that should not be publicly accessible. Use `get [filename]` to retrieve the flag from these directories, demonstrating the security risk involved.

## ***Meow Box***

### Introduction
- Focus on exploiting the Telnet protocol, a network communication protocol used for interactive communication between two remote systems.

### Enumeration
- Scan for open Telnet ports using Nmap with the command `nmap -p 23 -sV [target IP]`. Test common default credentials during initial access attempts to identify weak security practices.

### Foothold
- Use a command like `telnet [target IP]` to connect using default credentials, particularly common usernames with no passwords. Once connected, use commands like `ls` and `cd` to navigate the system and locate the flag in a directory that should have restricted access, emphasizing the need for strong credential policies.

## ***Dancing Box***

### Introduction
- Delve into the exploitation of SMB protocol misconfigurations, which is commonly used for network file sharing.

### Enumeration
- Employ `smbclient -L \\[target IP]` to connect to and list available SMB shares. Identify shares with improper permissions or unprotected resources.

### Foothold
- Access and download files from SMB shares that lack proper permissions using `smbclient \\[target IP]\\[share name]`. Focus on locating the flag file to highlight the impact of not implementing adequate access controls and permissions. Use the `get [filename]` command within `smbclient` to download the flag.

## ***Redeemer Box***

### Introduction
- Engage with Redis, an in-memory data structure store, focusing on securing databases against common configuration oversights.

### Installing redis-cli
- Install the Redis command-line interface using the command `sudo apt install redis-tools`. This enables direct interaction with Redis databases through command-line commands.

### Enumerating Redis Server
- Use `redis-cli -h [target IP]` to connect to the Redis server. Execute commands like `INFO` to gather detailed information about the database, identifying potential misconfigurations and data leakage.

### Interaction and Data Retrieval
- Apply various Redis commands to interact with the server and retrieve data. Use `KEYS *` to list all keys in the database, and `GET [key name]` to retrieve the value of specific keys, demonstrating data access vulnerabilities.

### Flag Retrieval
- Locate and retrieve the flag from the database by first finding the key that stores the flag using `KEYS *` to list all keys, and then retrieving the flag using `GET [flag key name]`, showcasing how to exploit the system successfully and stressing the importance of securing in-memory databases from unauthorized access.

## ***Appointment Box***

### Introduction
- Focus on exploiting SQL Injection vulnerabilities within web applications. This involves manipulating SQL queries through user inputs to gain unauthorized access to databases that are not intended to be publicly accessible.

### Enumeration
- Begin with an Nmap scan to identify open ports and services. Use the command `nmap -sC -sV [target IP]` to perform script scanning and version detection, which can provide detailed information about the services running on the target.

### Using Gobuster
- To discover hidden directories or files within the web server, employ Gobuster. Install Gobuster if it’s not already present in your system. Use the command `gobuster dir -u http://[target IP] -w [path to wordlist]` to initiate the directory brute-forcing process.

#### Installation of Gobuster
- Gobuster can be installed via Go language. Use `go install github.com/OJ/gobuster/v3@latest` for a direct installation or clone the repository using `git clone https://github.com/OJ/gobuster.git` and build from source. Ensure you have Go installed and configured correctly.

### Foothold
- Check the login form for SQL Injection vulnerabilities. Manipulate the SQL query via input fields to bypass authentication processes. For instance, inputting `admin' --` in the username field might comment out the rest of the SQL query, potentially allowing unauthorized access without a password.

#### Example of SQL Injection
- Here is a basic example of how to perform SQL Injection:
  ```sql
  SELECT * FROM users WHERE username='admin' --' AND password='[ANY PASSWORD]'
  ```

## ***Sequel Box***

### Introduction
- This box focuses on navigating databases to understand how critical data such as usernames and passwords are stored and managed. Learning to interact directly with databases like MySQL and MariaDB is essential for exploiting database vulnerabilities.

### Enumeration
- Begin with an Nmap scan to identify open services and their respective ports. Use `nmap -sC -sV [target IP]` to perform script scanning and version detection. Look particularly for database service ports, commonly MySQL/MariaDB on port 3306.

### Foothold
- Install MySQL or MariaDB on your local machine to interact with the database. Use `sudo apt update && sudo apt install mysql*` to install all necessary MySQL packages.
- Attempt to connect to the MySQL service using `mysql -h [target IP] -u root`. This attempts a connection as the `root` user, which typically has the highest level of privileges. Check for configurations that might allow passwordless authentication, which can be a sign of misconfiguration or intended for initial setup phases.

#### Navigating the Database
- Once connected, use the following SQL commands to explore the database structure and contents:
  - `SHOW databases;`: Lists all databases accessible to the user.
  - `USE [database_name];`: Selects a database to interact with.
  - `SHOW tables;`: Displays tables within the currently selected database.
  - `SELECT * FROM [table_name];`: Retrieves all entries from a specified table.

### Result
- Successfully navigating the database allows you to locate and retrieve critical information, such as configuration details and user data. In this scenario, accessing the `config` table within the `htb` database reveals the flag, demonstrating effective database exploitation and data retrieval.


## ***Crocodile Box***

### Introduction
- This scenario emphasizes the importance of chaining together different exploitation vectors to gain a foothold on a target. It involves insecure FTP configurations and weak administrative controls on web applications, showcasing how credentials left in publicly accessible locations can lead to deeper system access.

### Enumeration
- Start with a thorough nmap scan using `-sC` for default script scanning and `-sV` for service version detection. Discover the services running on open ports, focusing particularly on FTP (port 21) and HTTP (port 80) services. Identify opportunities for anonymous FTP access which can often reveal sensitive information.

### Foothold
- Connect to the FTP server using `ftp [target IP]` and attempt anonymous access. If successful, use commands like `dir` to list directory contents and `get` to download potential configuration files or credential lists.
- Review the downloaded files for usernames and passwords which might be reused on other services such as the webserver running on the target.
- If FTP does not yield elevated access (`530 This FTP server is anonymous only`), shift focus to the webserver. Use browser tools like Wappalyzer to identify the technologies used on the site and explore potential vulnerabilities.
- Employ directory brute-forcing tools like Gobuster with the command `gobuster dir --url http://[target IP] --wordlist [path] -x php,html` to discover hidden or restricted directories like `/login.php`.
- Attempt to use discovered credentials on the web application login page. Successful login could lead to accessing administrative panels or sensitive server functions.

### Result
- Leveraging both loose FTP configurations and weak web application security practices can lead to significant unauthorized access, demonstrating the need for comprehensive security practices across all services. Successfully obtaining and utilizing credentials from one service on another underscores the interconnected risks present in multi-service environments.

## ***Responder Box***

### Introduction
- Focuses on exploiting NTLM authentication vulnerabilities within a Windows environment using a combination of tools like Responder and John the Ripper. The lab demonstrates the interception of NetNTLMv 2 hashes through a File Inclusion vulnerability on a Windows web server.

	**The NTLM authentication process is done in the following way:**
	1. The client sends the user name and domain name to the server.
	2. The server generates a random character string, referred to as the challenge.
	3. The client encrypts the challenge with the NTLM hash of the user password and sends it back to the Server.
	4. The server retrieves the user password (or equivalent).
	5. The server uses the hash value retrieved from the security account database to encrypt the challenge
	String. The value is then compared to the value received from the client. If the values match, the client
	Is authenticated.

### Enumeration
- Conduct a comprehensive nmap scan to identify open ports and services, utilizing flags such as `-p-` for scanning all ports, `--min-rate` to speed up the scan, and `-sV` for service version detection. This helps in discovering services like Apache on port 80 and WinRM on port 5985 which are crucial for further attacks.

### Website Enumeration
- Initial access to the website might involve adjusting DNS resolution by adding entries to the `/etc/hosts` file for name resolution, followed by using the website’s functionality to explore potential vulnerabilities such as language selection features that might allow for Local File Inclusion (LFI).

### File Inclusion Vulnerability
- Investigate the LFI vulnerability by manipulating the URL parameter to include system files or potentially sensitive files from the server’s filesystem. This includes testing well-known files and directories specific to Windows environments for inclusion in web responses.

### Responder Challenge Capture
- Utilize the Responder tool to set up a malicious SMB server that captures NTLM hashes when the server attempts to authenticate to the SMB share. This involves configuring the PHP server to misinterpret a URL parameter, prompting it to fetch a file over SMB, which triggers the NTLM authentication process.

### Using Responder
- Set up Responder on the attacking machine to listen for SMB requests and capture NTLMv 2 hashes. This requires adjusting the PHP configuration to allow SMB URLs, setting up the local environment to capture hashes, and ensuring network configurations are correct to intercept the authentication attempts.

### Hash Cracking
- After capturing the NTLMv 2 hash, use John the Ripper to crack it by comparing the hash against known password hashes from a wordlist. This step is crucial in obtaining valid credentials that can be used to access other services such as WinRM.

### WinRM
- Utilize the cracked credentials to gain access to the WinRM service on the target machine. This can be achieved using tools like Evil-WinRM to establish a remote session with administrative privileges, potentially leading to full control over the target machine.

### Result
- The successful exploitation of the File Inclusion vulnerability to capture NTLMv 2 hashes and crack them provides deep insights into how seemingly small misconfigurations can lead to significant security breaches. Gaining administrative access through WinRM demonstrates the critical impact of securing authentication mechanisms in Windows environments.


## ***Three Box***

### Introduction
- This scenario focuses on exploiting a poorly configured AWS S3 bucket in a Linux environment to upload and execute a reverse shell. It highlights the importance of secure cloud configuration to prevent unauthorized access and data breaches.

### Enumeration
- Begin with an nmap scan to identify open ports, specifically looking for HTTP (port 80) and SSH (port 22). Use commands like `sudo nmap -sV [target IP]` to determine the services running on these ports.

### Sub-domain Enumeration
- Investigate potential subdomains using tools like Gobuster, identifying services such as a misconfigured S3 bucket subdomain (e.g., S3. Thetoppers. Htb). This step involves DNS adjustments in the `/etc/hosts` file to resolve new subdomains for further exploration.

### What is an S3 Bucket?
- Understand the functionality of AWS S3 buckets as cloud-based storage solutions. Identify the bucket in use by the target application for storing web content, which can include sensitive configuration files or executable scripts.

### Exploiting the S3 Bucket
- Utilize the AWS CLI tool to interact with the S3 bucket, checking for publicly accessible files or misconfigured permissions that allow file uploads. Use `aws --endpoint=http://s3.thetoppers.htb s3 ls` to list contents and `aws --endpoint=http://s3.thetoppers.htb s3 cp [file] s3://thetoppers.htb` to upload files.
- Explore uploading a PHP reverse shell script to the S3 bucket, which is being used as the webroot by the Apache server. This allows for remote code execution by navigating to the script via a web browser.

### Gaining a Reverse Shell
- After uploading the PHP reverse shell, execute it by accessing the file through the web browser with a parameter that triggers a system command. This can lead to obtaining a reverse shell if the server's configuration permits executing such scripts.
- Establish a listener on your local machine using tools like `nc` and then trigger the server to connect back to this listener, completing the reverse shell connection.

### Result
- Successfully exploiting the S3 bucket to upload and execute a reverse shell demonstrates significant security flaws in the cloud configuration. It underscores the need for rigorous security measures in cloud environments to protect against unauthorized access and potential data leaks.


## ***Archetype Box***

### Introduction
- Archetype is a Windows machine where the challenge involves exploiting a misconfiguration in Microsoft SQL Server. This scenario provides an opportunity to use tools like Impacket to exploit services and understand how to gain unauthorized access using misconfigurations.

### Enumeration
- Begin with an nmap scan to identify open services, specifically targeting SMB and Microsoft SQL Server running on port 1433. Use `nmap -sC -sV {TARGET_IP}` to perform this scan, which helps in discovering services that are potentially exploitable.

### Foothold
- Explore SMB shares using `smbclient` to locate and access interesting files, such as the `prod.dtsConfig`, which might contain sensitive information. Use the command `smbclient -N \\\\{TARGET_IP}\\backups` to interact with the shares and `get prod.dtsConfig` to download files that may include credentials or configuration details.
- Utilize the credentials found in the configuration file to authenticate to the MSSQL server using Impacket's `mssqlclient.py`. This step includes understanding the functionalities provided by the script and effectively using them to interact with the SQL Server.

### Privilege Escalation
- After gaining access to the SQL server, investigate further exploitation opportunities like enabling and using `xp_cmdshell` to execute system commands directly from the SQL server. This can lead to gaining a reverse shell using tools such as `nc` (Netcat).
- Transfer necessary binaries or scripts to the target machine using SMB or HTTP, depending on the scenario and the permissions associated with the user context under which the SQL service is running.

### Result
- Successfully exploiting the misconfigurations in SMB and SQL Server not only grants unauthorized access but also allows for deeper system interaction, potentially leading to full system control if administrative privileges can be escalated. This scenario exemplifies the critical importance of securing configuration files and service settings on servers.


## ***Oopsie Box***

### Introduction
- "Oopsie" is an educational scenario focused on exploring common web vulnerabilities like Information Disclosure and Broken Access Control. The scenario highlights the importance of thoroughly understanding how authentication mechanisms and access control are implemented in web applications.

### Enumeration
- Start with an nmap scan to identify open ports and services, particularly focusing on port 22 (SSH) and port 80 (HTTP). Explore the web application using a web browser and tools like Burp Suite to understand the site structure and identify potential entry points for further exploitation.

### Foothold
- Use Burp Suite to passively spider the website, identifying hidden directories and files such as the `/cdn-cgi/login` directory, which contains the login page. Explore functionalities available to guest users and attempt to escalate privileges by manipulating cookies and session information.

### Lateral Movement
- Investigate possible ways to escalate privileges from a guest user to a super admin role by manipulating cookies in the browser. Explore the application’s response to changes in cookie values to access restricted areas of the website, such as the uploads section.

### Privilege Escalation
- After gaining access to sensitive functionalities like file uploads, attempt to upload a PHP reverse shell to gain remote command execution. Use tools like netcat to listen for incoming connections from the web server, establishing a reverse shell session.

### Result
- Successfully exploiting the web application through a series of vulnerabilities—from information disclosure to broken access control—demonstrates the compound effect of seemingly minor security issues. Gaining a reverse shell and escalating privileges within the system highlights the critical need for comprehensive security measures in web applications.


## ***Vaccine Box***

### Introduction
- The "Vaccine" scenario emphasizes the importance of enumeration and the power of password cracking in penetration testing. It demonstrates that even systems that appear secure can often be accessed through chaining minor vulnerabilities or exploiting common misconfigurations like weak passwords.

### Enumeration
- Begin with an nmap scan to identify open services, focusing on FTP (port 21), SSH (port 22), and HTTP (port 80). Explore the FTP service to discover and download files such as `backup.zip`, which requires password extraction and potentially contains sensitive information.

### Foothold
- Utilize tools like John the Ripper to crack the password of the `backup.zip` file. Extract contents such as configuration files or scripts that might contain credentials or hints for further exploitation. Use these credentials to access other parts of the system, such as a web administration interface.

### Privilege Escalation
- After gaining initial access, explore further for SQL injection vulnerabilities using tools like SQLmap. Leverage found vulnerabilities to execute commands on the server or escalate privileges. Explore common web application files and configurations for additional credentials or misconfigurations.
- Utilize any disclosed credentials to attempt SSH access or further elevate privileges through potential sudo misconfigurations or exploitable system processes.

### Result
- Successfully exploiting the chain of vulnerabilities from weak passwords to SQL injection demonstrates the layered approach often necessary in penetration testing. It highlights the critical importance of thorough enumeration and the effective use of various tools to uncover and exploit vulnerabilities in a system.


## ***Unified Box***

### Introduction
- The "Unified" scenario provides an exploration of exploiting the Log4J vulnerability in a network appliance monitoring system called "UniFi". This box demonstrates setting up necessary tools to exploit the Log4J vulnerability, manipulate HTTP headers for reverse shell access, and manipulate data within a MongoDB database to gain administrative access.

### Enumeration
- Begin by scanning the target with Nmap to identify open ports and services, focusing on HTTP and HTTP proxy services. This helps in identifying potential entry points such as web portals where vulnerabilities like Log4J can be exploited.

### Exploitation
- Utilize the Log4J vulnerability by crafting malicious inputs in HTTP headers to execute remote code. Set up an environment to capture and execute incoming LDAP requests by using tools like `tcpdump` and `Rogue-JNDI`, which help in executing arbitrary code on the vulnerable system.

### Privilege Escalation
- Once initial access is gained, focus on escalating privileges by manipulating data stored in MongoDB. Change administrative credentials within the database to gain higher-level access to the system. Additionally, explore the system to uncover further exploitable misconfigurations or credentials that could lead to gaining root access.

### Result
- Successfully exploiting the system through the Log4J vulnerability and subsequent manipulation of database entries demonstrates complex attack vectors that combine software flaws with misconfigurations. This scenario underscores the critical need for thorough security configurations and regular updates to both software and administrative credentials.

