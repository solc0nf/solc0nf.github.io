var relearn_search_index = [
  {
    "content": "Articles about common exploits will be posted under this section.\nInformation contained in these articles have been sourced from various sites during the course of my studies. I have tried to construct the articles in such a way that it would be easy for beginners in the field (Infosec, or Information Security) to understand. The material provided here is intended solely for educational purposes only. I intend no copyright infringement of any kind. List of sites I have collated the material from, will be mentioned wherever possible. The information contained in this post is intended solely to provide general guidance on matters of interest for the personal use of the reader, who accepts full responsibility for its use. While every attempt has been made to ensure that the information contained on this article has been obtained from reliable sources, I am not responsible for any errors or omissions, or for the results obtained from the use of this information.\n",
    "description": "",
    "tags": null,
    "title": "Exploit Articles",
    "uri": "/exploit-articles/index.html"
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
    "title": "exploit",
    "uri": "/tags/exploit/index.html"
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
    "title": "Categories",
    "uri": "/categories/index.html"
  }
]
