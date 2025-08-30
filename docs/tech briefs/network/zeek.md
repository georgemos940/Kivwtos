# Introduction To Network Monitoring Approaches
Network monitoring is the continuous observation and optional retention of network traffic for later analysis. Objectives include detecting and reducing network problems, improving performance, and supporting productivity. It is a staple of daily IT operations and differs from Network Security Monitoring (NSM) in purpose and scope.

# Network Monitoring
Focus on uptime/availability, device health, connection quality (latency, loss, jitter), and traffic balance/configuration. Activities include traffic visualization, troubleshooting, and root-cause analysis. This model primarily serves network administrators and usually does not cover deep, non-asset vulnerabilities or advanced security concerns such as insider threats and zero-day exploitation. Typically it sits outside a SOC and belongs to enterprise IT/network management.

# Network Security Monitoring
Focus on anomalies and threat activity: rogue hosts, suspicious encrypted flows, odd services/ports, and malicious/suspicious traffic patterns. Traffic visualization and investigation of suspicious events are core. It is used by security analysts, incident responders, security engineers, and threat hunters. It relies on rules/signatures/behavioral patterns and operates in the SOC with tiered roles (Tier 1–2–3).

---

# Zeek Overview
Zeek (formerly Bro) is a passive traffic analysis framework originating from Lawrence Berkeley National Lab. It is both open-source (community maintained) and commercial (Corelight enterprise distribution). Zeek stands out by producing a broad set of detailed, structured logs usable for forensics and analytics, more than fifty log types across multiple categories.

![Hashing Example](../../assets/img30.png)

---
# Zeek Vs Snort
While both are IDS/NIDS, each excels at different goals. Zeek emphasizes broad NSM analytics and event correlation; Snort emphasizes signature-driven detection/prevention.

| Tool  | Capabilities                                            | Cons                                                            | Pros                                                                                                   | Common Use Case                                             |
|------|-----------------------------------------------------------|------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| Zeek | NSM + IDS framework, heavy focus on network analysis and event semantics | Harder to use; much analysis occurs outside the core unless scripted/automated | In-depth visibility; strong for threat hunting; complex, chained threat detection; scripting + correlation | Network monitoring; deep traffic investigation; chained-event intrusion detection |
| Snort| IDS/IPS focused on signatures and packet-level patterns   | Weaker at complex multi-stage behaviors                          | Easy-to-read logs; easy rule authoring; large community; vendor-backed (e.g., Cisco rules)             | Intrusion detection & prevention; stopping known attacks    |

# Architecture
Two primary layers:
- Event Engine: Packet processing/core event description. Identifies src/dst, protocols, sessions, and extracts files.
- Policy Script Interpreter: Semantic/correlation layer that applies Zeek scripts to derive meaning, create notices, and orchestrate responses.

# Frameworks (Selected)
Logging, Notice, Input, Configuration, Intelligence, Cluster, Broker Communication, Supervisor, GeoLocation, File Analysis, Signature, Summary, NetControl, Packet Analysis, TLS Decryption. These extend Zeek in the scripting layer and are typically enabled with `@load ...`.

# Outputs (Logs) And Default Paths
Zeek emits tab-separated ASCII logs; each session has a unique UID for correlation. By default when running as a service, logs live under:
- /opt/zeek/logs/

# Log Categories (Examples)
| Category             | Description                                    | Example Logs                                                                                                     |
|----------------------|------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| Network Protocols    | Protocol-level activity                        | conn.log, dce_rpc.log, dhcp.log, dnp3.log, dns.log, ftp.log, http.log, irc.log, kerberos.log, modbus*.log, mysql.log, ntlm.log, ntp.log, radius.log, rdp.log, rfb.log, sip.log, smb_cmd.log, smb_files.log, smb_mapping.log, smtp.log, snmp.log, socks.log, ssh.log, ssl.log, syslog.log, tunnel.log |
| Files                | File analysis results                          | files.log, ocsp.log, pe.log, x509.log                                                                            |
| NetControl           | Network control & flow actions                 | netcontrol.log, netcontrol_drop.log, netcontrol_shunt.log, netcontrol_catch_release.log, openflow.log            |
| Detection            | Detections/indicators                          | intel.log, notice.log, notice_alarm.log, signatures.log, traceroute.log                                          |
| Observations         | Environment summaries                           | known_certs.log, known_hosts.log, known_modbus.log, known_services.log, software.log                             |
| Miscellaneous        | External alerts/inputs/failures                | barnyard2.log, dpd.log, unified2.log, unknown_protocols.log, weird.log, weird_stats.log                          |
| Diagnostics          | System and script diagnostics                  | broker.log, capture_loss.log, cluster.log, config.log, loaded_scripts.log, packet_filter.log, print.log, prof.log, reporter.log, stats.log, stderr.log, stdout.log |

# Update Cadence (Typical)
| Frequency   | Log Name         | Description                                       |
|-------------|-------------------|---------------------------------------------------|
| Daily       | known_hosts.log   | Hosts that completed TCP handshakes               |
| Daily       | known_services.log| Services observed                                 |
| Daily       | known_certs.log   | Observed TLS certificates                         |
| Daily       | software.log      | Software fingerprints seen on the network         |
| Per session | notice.log        | Anomalies detected                                |
| Per session | intel.log         | Traffic matched to indicators                     |
| Per session | signatures.log    | Matched signatures                                |

# Investigation Blueprint (Log Usage Primer)
Overall info: conn.log, files.log, loaded_scripts.log, intel.log  
Protocol deep dive: http.log, dns.log, ftp.log, ssh.log  
Detection: notice.log, signatures.log, pe.log, traceroute.log  
Observations: known_hosts.log, known_services.log, software.log, weird.log

# Operating Modes
- Service/Live: Continuous interface monitoring via Zeek + ZeekControl.
- Offline/Pcap: Process captures and produce the same logs.

# Core Command-Line Parameters
| Parameter | Description                               |
|-----------|-------------------------------------------|
| -r        | Read/process a pcap file                  |
| -C        | Ignore checksum errors                    |
| -v        | Print version info                        |
| zeekctl   | ZeekControl module (service management)   |

# Working With Zeek (Examples)
Check version:
```
zeek -v
```
Manage service (requires privileges):
```
zeekctl
zeekctl status
zeekctl start
zeekctl stop
```

Process a pcap (ignore checksum):
```
zeek -C -r sample.pcap
```

Locate logs:
```
ls -l
ls -l /opt/zeek/logs/
```

# ZeekControl Session (Illustrative)
```
root@ubuntu$ zeekctl
Welcome to ZeekControl 2.X.0
[ZeekControl] > status
Name         Type       Host          Status    Pid    Started
zeek         standalone localhost     stopped
[ZeekControl] > start
starting zeek ...
[ZeekControl] > status
Name         Type       Host          Status    Pid    Started
zeek         standalone localhost     running   2541   13 Mar 18:25:08
[ZeekControl] > stop
stopping zeek ...
[ZeekControl] > status
Name         Type       Host          Status    Pid    Started
zeek         standalone localhost     stopped
```

# CLI Kung-Fu (Unix Text Processing)
| Category | Command / Pattern                               | Purpose                                    |
|----------|--------------------------------------------------|--------------------------------------------|
| Basics   | history; !!; !10                                 | Recall/execute prior commands              |
| Read     | cat file; head file; tail file                   | View files                                 |
| Find     | grep 'pattern' file                              | Filter lines                               |
| Cut      | cut -f 1; cut -d '.' -f 1-2                      | Select fields / subfields                  |
| Sort     | sort; sort -n; sort -nr                          | Sort alphanumerically/numerically          |
| Unique   | uniq; uniq -c                                    | De-duplicate / count duplicates            |
| Counts   | wc -l                                            | Count lines                                |
| Numbering| nl file                                          | Number lines                               |
| Sed      | sed -n '10,15p' file; sed -n '11p' file          | Print ranges/specific line                 |
| Awk      | awk 'NR < 11 {print $0}' file; awk 'NR==11{print $0}' | Select by row number                   |
| Special  | zeek-cut                                         | Extract named fields from Zeek logs        |

Extract fields from conn.log:
```
cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p
```

# Zeek-Cut Demo (Concept)
```
fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service ...
1488571051.943250 CTMFXm1AcIsSnq2Ric 192.168.121.2 51153 192.168.120.22 53 udp dns ...
1488571038.380901 CLsSsA3HLB2N6uJwW   192.168.121.10 50080 192.168.120.10 514 udp -  ...
cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p
CTMFXm1AcIsSnq2Ric udp 192.168.121.2  51153 192.168.120.22 53
CLsSsA3HLB2N6uJwW   udp 192.168.121.10 50080 192.168.120.10 514
```

# Signatures (Structure And Usage)
Zeek signatures combine: signature id, conditions, action.

| Component  | Details                                                                                                     |
|------------|-------------------------------------------------------------------------------------------------------------|
| Header     | src-ip, dst-ip, src-port, dst-port, ip-proto (TCP/UDP/ICMP/ICMP6/IP/IP6)                                    |
| Content    | Payload regex; decoded HTTP request/headers/body; reply headers/body; FTP command stream                    |
| Context    | same-ip checks and other contextual filters                                                                  |
| Operators  | ==, !=, <, <=, >, >= (strings, numbers, regex)                                                               |
| Action     | Default: write to signatures.log; optional: trigger events/scripts for correlation                           |

Run Zeek with signature file (.sig):
```
zeek -C -r sample.pcap -s sample.sig
```

Example: HTTP Cleartext Password
```
signature http-password {
  ip-proto == tcp
  dst-port == 80
  payload /.*password.*/
  event "Cleartext Password Found!"
}
```

Execute & inspect:
```
zeek -C -r http.pcap -s http-password.sig
cat notice.log     | zeek-cut id.orig_h id.resp_h msg
cat signatures.log | zeek-cut src_addr dest_addr sig_id event_msg
cat signatures.log | zeek-cut sub_msg
```

Example outputs (illustrative):
```
10.10.57.178 44.228.249.3 10.10.57.178: Cleartext Password Found!
POST /userinfo.php HTTP/1.1... Host: testphp.vulnweb.com ...
```

Example: FTP Admin Attempt
```
signature ftp-admin {
  ip-proto == tcp
  ftp /.*USER.*dmin.*/
  event "FTP Admin Login Attempt!"
}
```

Example: FTP Brute-Force Via Response Code
```
signature ftp-brute {
  ip-proto == tcp
  payload /.*530.*Login.*incorrect.*/
  event "FTP Brute-force Attempt!"
}
```

Grouped signatures in one file (username + brute):
```
signature ftp-username { ip-proto == tcp ftp /.*USER.*/ event "FTP Username Input Found!" }
signature ftp-brute    { ip-proto == tcp payload /.*530.*Login.*incorrect.*/ event "FTP Brute-force Attempt!" }
```

# Scripting (101 → 201)
Zeek scripts are event-driven and as expressive as high-level languages. Base scripts live under /opt/zeek/share/zeek/base (do not modify). Site/local scripts under /opt/zeek/share/zeek/site. Policy scripts under /opt/zeek/share/zeek/policy. Configuration at /opt/zeek/share/zeek/site/local.zeek. Scripts use the .zeek extension. Zeek is event-oriented (not packet-oriented).

Load scripts in live mode via local.zeek (load @/path or load @name), or run a script for a single offline analysis.

Events:
```
zeek_init()       # Fires at start
zeek_done()       # Fires at end
new_connection(c) # Per new connection
signature_match(state,msg,data) # Signature hit
```

Examples:
```
event zeek_init() { print("Started Zeek!"); }
event zeek_done() { print("Stopped Zeek!"); }
```

Run:
```
zeek -C -r sample.pcap 101.zeek
```

Dump raw connection structure:
```
event new_connection(c: connection) { print c; }
```

Selective pretty print:
```
event new_connection(c: connection) {
  print "###########################################################";
  print "New Connection Found!";
  print fmt("Source Host: %s # %s --->", c$id$orig_h, c$id$orig_p);
  print fmt("Destination Host: %s # %s <---", c$id$resp_h, c$id$resp_p);
}
```

Script + signature correlation:
```
event signature_match (state: signature_state, msg: string, data: string) {
  if (state$sig_id == "ftp-admin") { print ("Signature hit! --> #FTP-Admin"); }
}
```

# Loading Built-Ins / Frameworks
Load all site-configured scripts (local):
```
zeek -C -r ftp.pcap local
```
# New logs may appear: loaded_scripts.log, capture_loss.log, notice.log, stats.log

Load a specific policy script:
```
zeek -C -r ftp.pcap /opt/zeek/share/zeek/policy/protocols/ftp/detect-bruteforcing.zeek
cat notice.log | zeek-cut ts note msg
... FTP::Bruteforcing ... had 20 failed logins on 1 FTP server in 0m1s
```

# File Analysis Framework (Hashing + Extraction)
Hash all observed files:
```
@load /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek
```
Run:
```
zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/hash-all-files.zeek
```
View:
```
cat files.log | zeek-cut md5 sha1 sha256
```

Extract all files:
```
zeek -C -r case1.pcap /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
ls extract_files
file extract_files/*
```

Correlate files with connections:
```
cat files.log | zeek-cut fuid conn_uids tx_hosts rx_hosts mime_type extracted
```
# Pivot on conn_uids into conn.log/http.log to get context (server, URI, UA)

# Intelligence Framework (Indicator Matching)
Intel file (tab-delimited): /opt/zeek/intel/zeek_intel.txt
```
#fields    indicator    indicator_type    meta.source    meta.desc
smart-fax.com  Intel::DOMAIN  zeek-intel-test  Zeek-Intelligence-Framework-Test
```

Script:
```
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
redef Intel::read_files += { "/opt/zeek/intel/zeek_intel.txt" };
```

Run:
```
zeek -C -r case1.pcap intelligence-demo.zeek
Inspect:
cat intel.log | zeek-cut uid id.orig_h id.resp_h seen.indicator matched
```

# Package Manager (ZKG)
| Command                      | Description                                        |
|------------------------------|----------------------------------------------------|
| zkg install <pkg or url>     | Install a package                                  |
| zkg list                     | List installed packages                            |
| zkg remove <package>         | Remove a package                                   |
| zkg refresh                  | Refresh package metadata                           |
| zkg upgrade                  | Update installed packages                          |

Install cleartext password detector:
```
zkg install zeek/cybera/zeek-sniffpass
```

Run:
```
zeek -Cr http.pcap zeek-sniffpass
```

Check:
```
cat notice.log | zeek-cut id.orig_h id.resp_h proto note msg

 => SNIFFPASS::HTTP_POST_Password_Seen ... Password found for user ...
```

Geolocation enrichment (depends on local GeoLite DB):
 - (e.g., geoip-conn)
```
zeek -Cr case1.pcap geoip-conn
cat conn.log | zeek-cut uid id.orig_h id.resp_h geo.orig.country_code geo.orig.region geo.orig.city geo.resp.country_code geo.resp.region geo.resp.city
```

# Directories & Do/Don't
```
Do not modify: /opt/zeek/share/zeek/base
Policy scripts: /opt/zeek/share/zeek/policy
Site/local scripts: /opt/zeek/share/zeek/site
Config: /opt/zeek/share/zeek/site/local.zeek
BIFs/protocols: /opt/zeek/share/zeek/base/bif, /opt/zeek/share/zeek/base/protocols
```

# Notes On Snort Rule Compatibility
Legacy Snort-to-Bro (snort2bro) is no longer supported in modern Zeek distributions; workflows diverged after rebranding.

# End-To-End Investigation Example (Conceptual)
-  Start broad: conn.log + files.log + intel.log; scan for outliers (rare ports, large transfers, new software).
-  Pivot by UID to dns/http/ssl/ssh/ftp to extract URLs, JA3/TLS certs, user-agents, credential patterns.
-  Inspect detection outputs: notice.log, signatures.log for corroborating signals.
-  Correlate extracted files (files.log, pe.log, x509.log) back to servers and sessions; hash, detonate, or block.
-  Summarize with known_hosts/services/software to see whether behavior is new or expected baseline.
-  Refine signatures/scripts or enable frameworks to improve recall/precision; feed indicators back into intel.

# Quick Reference – Parameter & Path Table
| Item             | Value / Example                                    |      |        |
| ---------------- | -------------------------------------------------- | ---- | ------ |
| Default logs dir | /opt/zeek/logs/                                    |      |        |
| Run pcap         | zeek -C -r sample.pcap                             |      |        |
| Service control  | zeekctl start                                      | stop | status |
| Version          | zeek -v                                            |      |        |
| Load local       | zeek -C -r pc.pcap local                           |      |        |
| Load script      | zeek -C -r pc.pcap /opt/zeek/share/zeek/policy/... |      |        |
| With signatures  | zeek -C -r pc.pcap -s rules.sig                    |      |        |

# Conclusion
Zeek is more than an IDS: It is a comprehensive network telemetry and analysis platform. By combining structured logs, signatures, an event-driven scripting language, and modular frameworks/packages, it enables deep visibility, correlation, and forensic power. In SOC operations Zeek complements signature-centric tools like Snort by adding context and multi-stage behavior detection, supporting both rapid triage and in-depth investigations.

---

<div style="text-align:center;">
  <iframe width="1000" height="563" src="https://www.youtube.com/embed/DtYl3tpdx1c" title="Network Forensics with Network Miner | TryHackMe SOC Level 1" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>
</div>