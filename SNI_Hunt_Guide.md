## **Hunt Guide: Encrypted Evasion & Metadata Fingerprinting**

### **1. The Hunting Hypothesis**

> **Adversary Behavior:** A threat actor is utilizing TLS 1.3 with ECH to bypass SD-WAN Application Identification (App-ID) and Web Filtering. By encrypting the "Inner SNI," the actor prevents the firewall from seeing the true destination, allowing C2 or exfiltration to hide behind a "benign" Cloudflare or CDN-owned outer hostname.

---

### **2. Network Layer Analysis**

* **Audit for ECH-Capable Traffic:** Filter your logs for the presence of the ECH extension (**0xfe0d** or **65037**) or ESNI (**0xffce**).
* **The "Reputation Gap":** Look for sessions where the **Outer SNI** belongs to a high-reputation CDN (Cloudflare, Akamai, Google) but the **JA3/JA4 Fingerprint** does not match a standard corporate browser.
* **Asymmetry Hunting:** Monitor for "asymmetric Flows"—encrypted sessions with an `Outbound:Inbound` byte ratio exceeding **20:1**. These are classic indicators of exfiltration, regardless of the SNI.

---

### **3. Metadata Fingerprinting (The JA3/JA4 Pivot)**

The fingerprint identifies the **software library** or **application** initiating the tunnel.

| Step | Technique | Goal |
| --- | --- | --- |
| **A. Extract** | Run the Python script on the source PCAP. | Get the 32-character MD5 hash. |
| **B. Lookup** | Search [JA3er.com](https://ja3er.com) or [Abuse.ch SSLBL](https://sslbl.abuse.ch). | Map the hash to a client (e.g., `rclone`, `Metasploit`, `python-requests`). |
| **C. Triage** | Check for "GREASE" values in the `ja3_string`. | Confirm if the client is a browser or a standalone script. |

---

### **Summary Checklist for the Hunter**

1. [ ] **Detect:** Identify ECH extensions in TLS Handshakes.
2. [ ] **Analyze:** Compare JA3 against known-good browser baselines.
3. [ ] **Pivot:** Correlate Network IP/Timestamp to an Endpoint Process.
4. [ ] **Expose:** Check DNS logs for ECH key bootstrap records.
---

### **Splunk Queries**
These Splunk queries are designed to help you execute the phases of the **Generic Hunt Guide** we built. Since you’re running a sophisticated setup on your **Lenovo P14s**, these searches leverage the high-fidelity fields found in Zeek, Suricata, or Cisco NVM logs.

---

### **1. Detection: Finding ECH Evasion**

This query identifies sessions where the client is attempting to hide the SNI. It looks for the specific extension ID `65037` (ECH) or `65486` (ESNI).

```splunk
index=network_logs (sourcetype="bro:ssl:json" OR sourcetype="suricata")
| eval ech_detected=if(like(ssl_extensions, "%65037%") OR like(ssl_extensions, "%65486%"), "Yes", "No")
| where ech_detected="Yes"
| table _time, src_ip, dest_ip, server_name, ja3, ssl_extensions
| rename server_name AS outer_sni

```

> **What this tells you:** It isolates every "Client Hello" that is intentionally encrypting its inner destination. If `outer_sni` is a common CDN (Cloudflare/Akamai) but the `src_ip` is a sensitive server, you have a high-priority anomaly.

---

### **2. Analysis: JA3 Fingerprint Outlier Hunting**

This query finds "First Time Seen" JA3 hashes. In a threat hunt, you aren't looking for the most common hash; you're looking for the one that only appears on a single host.

```splunk
index=network_logs sourcetype="bro:ssl:json" ja3="*"
| stats earliest(_time) AS first_seen, latest(_time) AS last_seen, values(src_ip) AS clients, count BY ja3
| eval isNew=if(first_seen > relative_time(now(), "-24h"), "New_Hash", "Established")
| where isNew="New_Hash" AND mvcount(clients) < 3
| sort + first_seen

```

> **What this tells you:** It filters out the noise of standard browsers (Chrome/Edge) and highlights "Rare" JA3 fingerprints that have appeared in your environment for the first time in the last 24 hours.

---

### **3. Correlation: The "Process-to-Packet" Bridge**

Once you have a suspicious `src_ip` and `timestamp` from your network logs, use this to find the process on the endpoint. This requires **Sysmon** or **EDR** data.

```splunk
index=endpoint_logs (sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3)
| where SourceIp="10.0.0.29" 
| bin _time span=1s
| join _time, SourceIp [
    search index=network_logs sourcetype="bro:ssl:json" 
    | bin _time span=1s 
    | rename id.orig_h AS SourceIp 
    | fields _time, SourceIp, ja3, server_name
]
| table _time, Image, CommandLine, User, ja3, server_name, DestinationIp

```

> **Note:** We use `bin _time span=1s` to align the timestamps of the network flow and the endpoint socket creation. This is the "smoking gun" that shows exactly which `.exe` created that ECH session.

---

### **4. Exfiltration: Detecting "Asymmetric Flows"**

```splunk
index=network_logs sourcetype="pan:traffic" OR sourcetype="cisco:nvm"
| eval ratio = bytes_out / bytes_in
| where ratio > 20 AND bytes_out > 10485760 
| table _time, src_ip, dest_ip, bytes_out, bytes_in, ratio, app
| sort - bytes_out

```

> **What this tells you:** It flags any encrypted session where the client sent more than 10MB and the outbound traffic was 20x larger than the inbound. This is the signature of a file upload (exfil).

---

### **Quick Reference: Key Hunt Fields**

| Field Name | Significance |
| --- | --- |
| **`ssl_extensions`** | Look for `65037` (ECH) or `65281` (Renegotiation Info). |
| **`ja3` / `ja3s**` | The client and server fingerprints. |
| **`server_name`** | The "Outer" SNI (often a decoy in ECH). |
| **`bytes_out`** | The primary indicator of exfiltration volume. |

---

[Evasion in Depth - Techniques Across the Kill-Chain](https://www.youtube.com/watch?v=IbA7Ung39o4)
This video provides a deep dive into the various evasion strategies used by red teams and advanced adversaries, which will help you understand the mindset behind using ECH and SNI spoofing for exfiltration.