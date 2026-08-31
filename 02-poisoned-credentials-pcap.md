# PoisonedCredentials Lab — Network Forensics Investigation

## 1. Scenario

The organisation's security team detected suspicious network activity suggesting that LLMNR
and NBT-NS poisoning attacks were occurring inside the network. These attacks exploit how
Windows machines broadcast hostname queries when DNS fails — an attacker can intercept
those broadcasts, respond falsely, and trick victims into handing over their credentials.

I was given a PCAP of the network traffic and tasked with identifying the mistyped query that
triggered the attack, the rogue machine responsible, the victims affected, the credentials
compromised, and where the attacker moved to afterward.

I was not familiar with LLMNR poisoning before this lab. A fair amount of what I learned came
from researching during and after the investigation, which I've tried to reflect honestly below.

---

## 2. Evidence Provided

| Item | Detail |
|---|---|
| File type | PCAP (network packet capture) |
| Analysis platform | CyberDefenders — PoisonedCredentials Lab |
| Tools | Wireshark |

---

## 3. Tools Used

| Tool | What I used it for |
|---|---|
| **Wireshark** | Filtering traffic, reading packet details, following conversations between machines |

Filters I used during the investigation:

```wireshark
llmnr                            # All LLMNR broadcast queries and responses
ip.src == 192.168.232.162        # Narrow down to queries from the first victim machine
ip.src == 192.168.232.215        # Narrow down to responses from the rogue machine
ntlmssp                          # NTLM authentication traffic
smb2                             # SMB file sharing and lateral movement traffic
```

I filtered by protocol name throughout — `llmnr`, `ntlmssp`, and `smb2` — rather than
by port numbers. Wireshark recognises these as named protocols so you don't need to
know the underlying port numbers. I didn't know most of these filters going in and built
up to them as I understood more about what protocols were involved at each stage.

---

## 4. Attack Timeline

| Time (UTC) | Event | How I found it |
|---|---|---|
| Start of capture | `192.168.232.162` broadcasts an LLMNR query for `fileshaare` — a mistyped hostname | `llmnr` filter, looked at query names in packet details |
| Shortly after | `192.168.232.215` (rogue machine) responds to the broadcast, claiming to be `fileshaare` | Same `llmnr` filter — response packets coming from the rogue IP |
| Shortly after | `192.168.232.176` also receives a poisoned response from the rogue machine | `llmnr` combined with `ip.src == 192.168.232.215`, found a second destination IP |
| Following poisoning | `192.168.232.162` and `192.168.232.176` attempt to authenticate to the rogue machine | `ntlmssp` filter — NTLMSSP_AUTH packets containing username `janesmith` |
| Post-authentication | Attacker uses captured credentials to access `AccountingPC` over SMB | `smb2` filter — hostname found in NTLMSSP_CHALLENGE packet (Session Setup Response) |

---

## 5. Key Findings

**1. Mistyped hostname query: `fileshaare`**
The attack started because a machine made a typo. `192.168.232.162` tried to reach a
host called `fileshaare` — likely meant to be `fileshare`. When DNS couldn't resolve it,
the machine fell back to LLMNR and broadcast the query to the entire network. I found this by filtering for LLMNR traffic directly using the `llmnr` filter in Wireshark —
I didn't need to know the port number because Wireshark recognises it as a named
protocol. I then narrowed it down by adding `ip.src == 192.168.232.162` to focus on
traffic from that specific machine.

**2. Rogue machine identified: `192.168.232.215`**
Using the same `llmnr` filter, I looked for response packets rather than query packets.
There's no legitimate machine called `fileshaare` on this network, so any response to that
query had to be malicious. `192.168.232.215` was the one answering — making it the rogue
machine. The logic here is simple once you understand it: if nobody should be answering,
whoever answers is the attacker.

**3. Second victim machine: `192.168.232.176`**
I filtered for all LLMNR responses sent by the rogue machine using `llmnr` combined with
`ip.src == 192.168.232.215` and looked at where those responses were going. I already knew
one went to `192.168.232.162`. A second response went to `192.168.232.176` — confirming
a second victim was poisoned.

**4. Compromised account: `janesmith`**
This is where I needed background knowledge I didn't have going in. Once a Windows
machine thinks it's found the server it was looking for, it tries to authenticate to it using
NTLM — the standard authentication protocol Windows uses for file servers and shared
resources. I filtered for `ntlmssp` and found NTLMSSP_AUTH packets — the ones that
contain the actual login attempt. Expanding the packet details showed the username in
plaintext: `janesmith`. The password itself was a hashed NTLMv2 value, not readable
directly, but the username was fully visible.

**5. Lateral movement to `AccountingPC` via SMB**
With `janesmith`'s credentials captured, I needed to find where the attacker used them.
On Windows networks, SMB is the protocol for accessing shared files and remote machines.
I filtered for `smb2` and looked through the Session Setup packets. The hostname wasn't
in a Tree Connect packet as I initially expected — the traffic after authentication was
encrypted so those packets weren't readable. Instead I found the answer in packet 241,
the NTLMSSP_CHALLENGE (Session Setup Response). This is the target machine's response
to the attacker's login request, and it contains the server's own hostname — `AccountingPC`
— as part of the challenge. The server essentially identified itself in its own response.

---

## 6. MITRE ATT&CK Mapping

I did this mapping after completing the investigation by reading the ATT&CK framework
descriptions and matching them to what I observed.

| Tactic | Technique | What I observed |
|---|---|---|
| Credential Access | T1557.001 — LLMNR/NBT-NS Poisoning | Rogue machine `192.168.232.215` responded to broadcast queries to intercept authentication |
| Credential Access | T1187 — Forced Authentication | Victims tricked into authenticating to the rogue machine, surrendering NTLMv2 hashes |
| Credential Access | T1040 — Network Sniffing | Attacker passively captured credentials from network traffic |
| Lateral Movement | T1021.002 — SMB/Windows Admin Shares | Attacker used captured credentials to connect to `AccountingPC` via SMB2 |
| Defence Evasion | T1078 — Valid Accounts | Attacker authenticated using `janesmith`'s legitimate credentials — no exploit needed |

---

## 7. Detection Opportunities

I'm still building my understanding of detection engineering, but based on what I saw in
this investigation, here's what I think could have caught this:

**Disable LLMNR and NBT-NS entirely**
This is the most effective prevention rather than detection. Neither protocol is needed on
most modern networks — DNS handles name resolution. Disabling them via Group Policy
removes the attack surface completely. This isn't a detection rule but it's the first
recommendation I'd make.

**Alert on LLMNR responses from unexpected hosts**
If only legitimate internal hosts should ever respond to LLMNR queries, any response
from an unknown or unexpected IP should trigger an alert. The rogue machine answering
a query for a hostname that doesn't exist is the clearest possible indicator.

**Alert on NTLM authentication to unknown hosts**
When a machine tries to authenticate via NTLM to a host that isn't in the expected list
of file servers or domain controllers, that's anomalous. In this case, victims were
authenticating to `192.168.232.215` — a machine that had no legitimate reason to be
receiving authentication requests.

**Alert on SMB connections originating from a machine that just received NTLM hashes**
Chaining these two events together — NTLM capture followed by SMB lateral movement
from the same source IP — would give high-confidence detection of the full attack in
progress.

---

## 8. Escalation Decision

If this were a real incident, I would escalate immediately at high severity.

The attacker successfully captured at least one user's NTLMv2 credentials and used them
to access another machine (`AccountingPC`) via SMB. We don't know yet what they accessed
on that machine or whether the hash was cracked offline for further use. I'd want to isolate
`192.168.232.215` from the network immediately, force a password reset for `janesmith`,
audit what was accessed on `AccountingPC` during the SMB session, and check whether
`192.168.232.215` has appeared in any other traffic across the capture.

I'd summarise it to a shift lead as: *"We have a confirmed LLMNR poisoning attack. One
account (janesmith) was compromised and used to access AccountingPC via SMB. The rogue
machine is 192.168.232.215 — it needs to come off the network now."*

---

## 9. What I Got Wrong

**I didn't know what LLMNR was before starting this lab.**
I had heard the term during GCIH study but hadn't really internalised how it works. I
spent time at the start of the investigation just reading about the protocol before I could
make sense of what I was seeing in the PCAP. That reading time was useful but it meant
my initial filtering was unfocused.

**I didn't know to look for NTLM after finding the poisoning.**
The connection between LLMNR poisoning and NTLM credential capture wasn't obvious to
me until I researched it. I understood that the victim was tricked into thinking the rogue
machine was a file server, but I didn't immediately know that Windows would then try to
authenticate via NTLM. This is foundational Windows networking knowledge I need to
build — understanding what happens at each step of a normal Windows authentication flow
would have made this much more intuitive.

**I didn't know SMB2 was the right filter for lateral movement.**
Similar gap — I needed to research what protocol Windows uses for remote file access
before I knew to look for SMB2. Once I understood that SMB is how Windows machines
share files and access each other remotely, the filter made complete sense. Building
a stronger mental model of common Windows protocols (LLMNR, NTLM, SMB, Kerberos)
is something I'm working on as I continue through these labs.

**I went looking for a Tree Connect packet that wasn't there.**
I initially expected to find the hostname in a Tree Connect packet — the SMB packet that
shows which share or machine the attacker connected to. But the post-authentication
traffic was encrypted SMB3, so those packets weren't readable. The hostname was
actually sitting in packet 241 — the NTLMSSP_CHALLENGE — which is the target machine
identifying itself during the login handshake. I only found this by going back and reading
the Session Setup packets carefully rather than assuming the answer had to be in a
specific packet type.
EOF