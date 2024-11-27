# Network Traffic Analysis - Apache Tomcat Server Incident

## Overview
This project investigates a suspected compromise of an Apache Tomcat web server. By analyzing a network capture (PCAP) file, the investigation identifies malicious activities, documents the attack vector, and provides actionable recommendations for securing Apache Tomcat servers.

---

## Objectives
1. Analyze the PCAP file to identify malicious traffic patterns.
2. Establish a timeline of the attack.
3. Identify the attacker’s IP address, tools, and techniques used.
4. Provide recommendations for securing the Apache Tomcat server against similar threats.

---

## Steps to Analyze the Incident

### Page 1: Initial Setup
1. Extract the `TomCat Takeover.zip` file using **7-Zip**.
2. Install required tools:
   - Wireshark
   - CyberChef
   - PowerShell
3. Configure the tools on a virtual machine.

![Page 1: Initial Setup](images/page1-initial-setup.png)

---

### Page 2: Open PCAP File
1. Open the PCAP file in Wireshark.
2. Adjust the time display format to UTC:
   - Navigate to `View > Time Display Format > UTC Date and Time`.

![Page 2: Open PCAP File](images/page2-open-pcap.png)

---

### Page 3: Analyze Traffic Capture
1. Inspect the packet timeline:
   - **Start Time**: 14:13:06
   - **End Time**: 14:27:37
   - Total packets captured: 21,070.
2. Record this information for later reference.

![Page 3: Analyze Traffic Capture](images/page3-traffic-capture.png)

---

### Page 4: Identify Top Talkers
1. Sort conversations by bytes in Wireshark to find the top communicators.
2. Record the top IP addresses and their communication ports.

![Page 4: Identify Top Talkers](images/page4-top-talkers.png)

---

### Page 5: SMB Communication
1. Locate SMB traffic:
   - Source: 10.0.0.115
   - Destination: 10.0.0.105
   - Port: 445
2. Note the account initiating requests (e.g., `root`).

![Page 5: SMB Communication](images/page5-smb-communication.png)

---

### Page 6: Export SMB Objects
1. Export SMB objects using Wireshark’s object export feature.
2. Save the objects to a local directory for further analysis.

![Page 6: Export SMB Objects](images/page6-export-smb.png)

---

### Page 7: Generate File Hashes
1. Use PowerShell to generate SHA256 hashes for the exported SMB objects:
   ```powershell
   Get-FileHash <file-path> -Algorithm SHA256

<h2>Page 8: Inspect HTTP Traffic</h2>
<ol>
    <li>Locate HTTP packets in Wireshark.</li>
    <li>Identify Packet 685 and follow the HTTP stream.</li>
    <li>Record any unusual <code>GET</code> or <code>POST</code> requests.</li>
</ol>
<img src="images/page8-http-traffic.png" alt="Page 8: Inspect HTTP Traffic" width="600">

<hr>

<h2>Page 9: Investigate /manager/html</h2>
<ol>
    <li>Focus on requests to the <code>/manager/html</code> endpoint.</li>
    <li>Record all <code>GET</code> and <code>POST</code> requests to this endpoint.</li>
    <li>Look for suspicious activity, such as file uploads.</li>
</ol>
<img src="images/page9-manager-html.png" alt="Page 9: Investigate /manager/html" width="600">

<hr>

<h2>Page 10: Decode Base64 Authorization</h2>
<ol>
    <li>Extract Base64-encoded credentials from HTTP traffic in Wireshark.</li>
    <li>Decode the Base64 string using CyberChef to reveal plaintext credentials.</li>
    <li>Record the decoded username and password.</li>
</ol>
<img src="images/page10-decode-credentials.png" alt="Page 10: Decode Base64 Authorization" width="600">

<hr>

<h2>Page 11: Analyze Open Ports</h2>
<ol>
    <li>Use SYN/ACK filters in Wireshark to identify open ports.</li>
    <li>Note ports such as 22 (SSH), 8080, and 8009 (Tomcat-specific).</li>
    <li>Verify port activity and correlate with malicious actions.</li>
</ol>
<img src="images/page11-open-ports.png" alt="Page 11: Analyze Open Ports" width="600">

<hr>

<h2>Page 12: Reverse Shell Activity</h2>
<ol>
    <li>Analyze TCP streams for evidence of reverse shell activity.</li>
    <li>Identify streams originating on Port 443.</li>
    <li>Use AbuseIPDB to trace and confirm malicious IP addresses.</li>
</ol>
<img src="images/page12-reverse-shell.png" alt="Page 12: Reverse Shell Activity" width="600">

<hr>

<h2>Page 13: Authentication Events</h2>
<ol>
    <li>Locate Packet 20553 for login authentication attempts.</li>
    <li>Verify if credentials captured in Base64 were successfully used.</li>
    <li>Identify the timestamp and IP address of the login attempt.</li>
</ol>
<img src="images/page13-authentication.png" alt="Page 13: Authentication Events" width="600">

<hr>

<h2>Page 14: Upload WAR Files</h2>
<ol>
    <li>Investigate HTTP POST requests related to file uploads.</li>
    <li>Look for file signatures indicating a WAR file (e.g., <code>.war</code> or ZIP format).</li>
    <li>Record the file type and any evidence of deployment.</li>
</ol>
<img src="images/page14-war-files.png" alt="Page 14: Upload WAR Files" width="600">

<hr>

<h2>Page 15: Analyze HTTP Streams</h2>
<ol>
    <li>Follow HTTP streams to observe any uploaded files or executed commands.</li>
    <li>Record paths accessed by the attacker, especially <code>/manager/html</code>.</li>
    <li>Note any unusual responses from the server.</li>
</ol>
<img src="images/page15-http-streams.png" alt="Page 15: Analyze HTTP Streams" width="600">

<hr>

<h2>Page 16: Detect Malicious Behavior</h2>
<ol>
    <li>Correlate reverse shell activity with the attacker’s IP address.</li>
    <li>Confirm unauthorized access and system compromise.</li>
    <li>Highlight timestamps of malicious behavior.</li>
</ol>
<img src="images/page16-malicious-behavior.png" alt="Page 16: Detect Malicious Behavior" width="600">

<hr>

<h2>Page 17: Recommendations for Apache Tomcat</h2>
<ol>
    <li>Disable or restrict access to <code>/manager/html</code> to trusted IPs.</li>
    <li>Enforce strong, unique credentials for all accounts.</li>
    <li>Regularly update Apache Tomcat to the latest version.</li>
</ol>
<img src="images/page17-recommendations-tomcat.png" alt="Page 17: Recommendations for Tomcat" width="600">

<hr>

<h2>Page 18: Further Analysis - Packet Metadata</h2>
<ol>
    <li>Review metadata for captured packets to cross-reference timestamps.</li>
    <li>Record additional anomalies or patterns that align with the attack timeline.</li>
</ol>
<img src="images/page18-metadata.png" alt="Page 18: Further Analysis" width="600">

<hr>

<h2>Page 19: SMB Object Content</h2>
<ol>
    <li>Open the extracted SMB objects using Notepad or another text viewer.</li>
    <li>Verify file content for suspicious or unexpected information.</li>
    <li>Record observations about each file.</li>
</ol>
<img src="images/page19-smb-content.png" alt="Page 19: SMB Object Content" width="600">

<hr>

<h2>Page 20: VirusTotal Results</h2>
<ol>
    <li>Upload SMB object hashes to VirusTotal for verification.</li>
    <li>Note if any files are flagged as malicious or suspicious.</li>
    <li>Save the VirusTotal report for documentation.</li>
</ol>
<img src="images/page20-virustotal.png" alt="Page 20: VirusTotal Results" width="600">

<hr>

<h2>Page 21: Reconstruct Attack Timeline</h2>
<ol>
    <li>Combine captured data to reconstruct the timeline of the attack.</li>
    <li>Map attacker actions from initial access to file uploads and system compromise.</li>
</ol>
<img src="images/page21-timeline.png" alt="Page 21: Reconstruct Attack Timeline" width="600">

<hr>

<h2>Page 22-29: Additional Analysis (Placeholder)</h2>
<p>Follow similar steps for deeper protocol investigations, tool-specific findings, and attacker behavior analysis.</p>
<img src="images/page22-29-placeholder.png" alt="Page 22-29: Additional Analysis" width="600">
