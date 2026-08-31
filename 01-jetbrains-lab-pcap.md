# JetBrains Lab — Network Forensics Investigation

## 1. Scenario

An attacker exploited a vulnerability in an organisation's web server, uploaded a webshell,
and gained control of the system. The compromised server was then used to carry out further
malicious activity, including tampering with credential files. I was given a PCAP of the network
traffic during the attack and tasked with piecing together what happened — identifying where
the attacker came from, how they got in, what they did, and how far they got.

This was my first time doing a network forensics challenge, and it was harder than I expected.
I've documented not just what I found but how I got there, including the dead ends.

---

## 2. Evidence Provided

| Item | Detail |
|---|---|
| File type | PCAP (network packet capture) |
| Analysis platform | CyberDefenders — JetBrains Lab |
| Tools | Wireshark |

---

## 3. Tools Used

| Tool | What I used it for |
|---|---|
| **Wireshark** | Opening the PCAP, filtering traffic, following TCP streams to read full conversations |

Filters I ended up using during the investigation:

```wireshark
http.request.method == POST               # Find all POST requests (uploads, form submissions)
http.request.uri contains "pluginUpload"  # Zero in on the file upload event
http.request.uri contains "NSt8bHTg"      # Track all attacker commands through the webshell
```

I didn't know all these filters from the start — I built up to them as I understood more about
what I was looking for. More on that in Section 9.

---

## 4. Attack Timeline

| Time (UTC) | Event | How I found it |
|---|---|---|
| Pre-attack | Attacker fingerprints the server — identifies it as TeamCity 2023.11.3 | GET request to `/app/rest/server`, server response body contained version info |
| Pre-attack | CVE-2024-27198 exploited — attacker bypasses authentication entirely | POST to `/app/rest/users` with no valid login credentials |
| Pre-attack | Attacker creates a new admin account: `c91oyemw:CL5vzdwLuK` | Visible in the HTTP stream response after the exploit POST |
| Pre-attack | `NSt8bHTg.zip` uploaded through the plugin upload page | POST to `/admin/pluginUpload.html`, multipart file upload, 1931 bytes |
| Pre-attack | Server extracts the ZIP — JSP webshell lands at `/plugins/NSt8bHTg/NSt8bHTg.jsp` | Subsequent POST traffic appearing to the same plugin path |
| 2024-06-30 08:03 UTC | Attacker runs their first command through the webshell | Earliest POST to `/plugins/NSt8bHTg/NSt8bHTg.jsp` |
| Post 08:03 | Multiple commands sent through the webshell | Repeated POSTs to the webshell path, each with a different command in the body |
| Post 08:03 | Attacker overwrites the admin credentials file | Command found in POST body: `bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'` |
| Post 08:03 | Attacker attempts to escape the container — fails | Command found in POST body: `docker run --rm -it -v /:/host ubuntu chroot /host` |

---

## 5. Key Findings

**1. Attacker's IP address: 23.158.56.196**
I started by filtering for POST requests (`http.request.method == POST`) because I knew
uploads and form submissions use POST. Most of the traffic was from internal IPs, but
`23.158.56.196` stood out immediately — it was sending POSTs to admin pages and plugin
upload endpoints. That's what led me to flag it as the attacker.

**2. The server was running TeamCity 2023.11.3**
I found this by following the TCP stream on the plugin upload packet. The server's response
headers were right there in the stream. I initially tried using `http.response` as a filter but
got no results — following the stream turned out to be the simpler approach. The version
`2023.11.3` was visible in the response, which I then looked up and confirmed as
JetBrains TeamCity.

**3. CVE-2024-27198 — authentication bypass**
Once I had the software and version, I searched for known vulnerabilities and found
CVE-2024-27198 — a critical flaw that lets an unauthenticated attacker reach any endpoint
by crafting a specific URL. This matched exactly what I saw in the PCAP: the attacker
created an admin account without ever logging in first.

**4. Webshell delivered through the plugin upload feature**
The attacker uploaded `NSt8bHTg.zip` through `/admin/pluginUpload.html` — a page that
exists to let admins add new features to TeamCity. The server automatically extracted the
ZIP, and the JSP webshell inside it ended up at a web-accessible path. I thought the `.zip`
extension was suspicious at first — it made more sense once I understood that plugin
systems expect archives and extract them automatically.

**5. Credential file overwritten (T1565.001 — Stored Data Manipulation)**
One of the webshell commands used a Linux shell redirect (`>`) to overwrite a credentials
file with new values. The `>` operator replaces the file's contents entirely, which is why
this is classified as stored data manipulation rather than just account tampering. The
command was:
```bash
bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'
```

**6. Failed container escape attempt (T1611 — Escape to Host)**
The last notable command the attacker ran tried to break out of the container by mounting
the host filesystem inside a new Docker container and using `chroot` to switch into it.
This is a well-known technique. It didn't work — either the Docker socket wasn't exposed,
or the container didn't have the privileges needed. I only learned what this command meant
after looking it up.
```bash
docker run --rm -it -v /:/host ubuntu chroot /host
```

---

## 6. MITRE ATT&CK Mapping

I mapped the attacker's actions to MITRE ATT&CK after completing the investigation.
Some of these I identified myself; others I confirmed by reading the ATT&CK framework
descriptions after the fact.

| Tactic | Technique | What I observed |
|---|---|---|
| Reconnaissance | T1595.002 — Vulnerability Scanning | Attacker probed `/app/rest/server` to get the TeamCity version |
| Initial Access | T1190 — Exploit Public-Facing Application | CVE-2024-27198 authentication bypass |
| Persistence | T1136.001 — Create Account: Local Account | New admin account `c91oyemw:CL5vzdwLuK` created via the exploited API |
| Persistence | T1505.003 — Web Shell | `NSt8bHTg.jsp` deployed via plugin upload and accessible via HTTP |
| Defence Evasion | T1027 — Obfuscated Files or Information | Random-looking filename `NSt8bHTg` likely chosen to avoid detection |
| Execution | T1059.004 — Unix Shell | Commands run via `bash -c` through the JSP webshell |
| Impact | T1565.001 — Stored Data Manipulation | Admin credentials file overwritten at `/tmp/Creds.txt` |
| Privilege Escalation | T1611 — Escape to Host | Docker container escape attempted but unsuccessful |

---

## 7. Detection Opportunities

I'm still learning how detection rules are written in practice, but based on what I saw in
this investigation, here's what I think would have caught this earlier:

**Unusual POST to the plugin upload page from an external IP**
The plugin upload page exists for admins — there's no reason an external IP should ever
be posting to it. An alert on any external POST to `/admin/pluginUpload.html` would have
flagged this immediately.

**User account created via the REST API without a valid session**
CVE-2024-27198 works because the attacker can hit the API without authenticating. Any
user creation request that doesn't have a valid session token attached should be treated
as anomalous and alerted on.

**POST requests to a JSP file under the plugins directory**
Legitimate plugins don't receive direct POST requests from the internet. Seeing repeated
POSTs to `/plugins/<anything>/<anything>.jsp` from an external IP is a strong indicator
of webshell interaction.

**A web server process running Docker commands**
A Java process (which is what TeamCity runs on) spawning a `docker run` command is not
normal behaviour. This should trigger an alert at the endpoint level.

---

## 8. Escalation Decision

If this were a real incident, I would escalate immediately and treat it as critical.

The attacker had full remote code execution, created a backdoor account, tampered with
credentials, and tried to break out of the container. None of this is ambiguous — it's a
confirmed compromise, not a suspected one. I'd want to immediately isolate the server,
revoke all active TeamCity sessions, rotate any credentials that were stored on or accessible
from the server, and check whether the Docker socket is exposed anywhere it shouldn't be.

I'd summarise it to a shift lead as: *"We have a confirmed webshell on the TeamCity server.
The attacker had RCE, overwrote an admin credentials file, and attempted a container escape.
Server needs to come offline now."*

---

## 9. What I Got Wrong

This section is the most honest part of the writeup.

**I didn't know why I was looking at POST requests at first.**
I applied the `http.request.method == POST` filter because the hint pointed me there. I
didn't fully understand at the time that POST is the method used for uploads and form
submissions — and therefore the natural place to look for file-based attacks. That
understanding came later, and now I'd reach for that filter instinctively.

**The `http.response` filter didn't work and I didn't know why.**
My first attempt to find the server version was to filter for HTTP responses using
`http.response`. It returned nothing. I spent time trying to figure out why before realising
Wireshark wasn't decoding that traffic as HTTP on that particular port. The simpler fix —
just follow the TCP stream from a packet I already had — took me longer to try than it
should have. I'll try stream following earlier next time before troubleshooting filters.

**I followed hints more than I followed my own reasoning.**
Some of the hints pointed me toward a specific URL (`/app/rest/server`) to find the server
version. That path would have worked, but I already had the version sitting in a TCP stream
I had open. I didn't notice because I was following the hint rather than reading what was
in front of me. In a real investigation there are no hints — I need to build the habit of
reading the evidence I have before going looking for new evidence.

**I didn't know what the Docker command meant until I looked it up.**
When I first saw `docker run --rm -it -v /:/host ubuntu chroot /host` in the webshell
traffic, I didn't immediately know it was a container escape attempt. I had to research it.
That's fine for now — but it's a gap I want to close by reading more about container
security and common post-exploitation techniques.
