# Network Traffic Analysis - Apache Tomcat Server Incident

## Description

This project investigates a network traffic capture file (PCAP) from a suspected incident involving the compromise of an Apache Tomcat web server. The goal of this investigation is to identify malicious activities, document the attack vector, and provide actionable recommendations to mitigate similar risks.

## Scenario

The SOC (Security Operations Center) team detected suspicious activity on a web server within the company's intranet. Network traffic was captured for analysis, revealing potential malicious activities leading to the compromise of the Apache Tomcat web server.

## Objectives

- Analyze the PCAP file to identify malicious traffic patterns.
- Determine the timeline of the attack.
- Identify the attacker’s IP address, tools, and techniques used.
- Provide recommendations for securing the Apache Tomcat server against similar threats.

---

## Steps

### Step 1: Preparation and Tool Setup

1. **Install Required Tools**:
   - Install [7-ZIP](https://www.7-zip.org/) for file extraction.
   - Install [Wireshark](https://www.wireshark.org/) for network traffic analysis.

2. **Unzip the File**:
   - Extract the contents of the `TomCat Takeover.zip` file using 7-ZIP.

3. **Set Time Zone in Wireshark**:
   - In Wireshark, navigate to `View > Time Display Format` and set it to `UTC Date and Time` for consistent time display during packet analysis.

 ![](https://i.imgur.com/UG5H9j5.png)
  ![](https://i.imgur.com/O9M3iiA.png)
  ![](https://i.imgur.com/PdHoYmA.png)

---

### Step 2: Inspect the Captured PCAP File

1. **Open the PCAP File in Wireshark**:
   - Load the PCAP file in Wireshark for packet analysis.
   - Observe that the capture covers a period from `14:13:06 to 14:27:37`, with a total of `21,070 packets` captured.
 ![](https://i.imgur.com/GOy1jV8.png)
![](https://i.imgur.com/medDjSg.png)
---

### Step 3: Analyze Packet Types

1. **Identify Packet Types**:
   - Review the different types of packets in the PCAP file (e.g., TCP, UDP, HTTP, SMB) to gain an initial understanding of the network traffic.
 ![](https://i.imgur.com/fUHOE0m.png)
---

### Step 4: Identify Top Talkers and Top Ports

1. **Sort by Bytes to Identify Top Talkers**:
   - In Wireshark, sort packets by bytes to identify the top talkers (IP addresses communicating the most).
   - Note these top talkers and their respective IP addresses for further analysis.

2. **Identify Top Ports**:
   - Similarly, sort packets by port numbers to identify the top ports being used.
   - Document these top ports for further investigation.
 ![](https://i.imgur.com/3Pf3rXJ.png)
![](https://i.imgur.com/XdS4zdY.png)
---

### Step 5: Investigate SMB Communication

1. **Identify SMB Communication**:
   - Notice that a communication is initiated from `10.0.0.115` to `10.0.0.105` on Port 445 (SMB port).
   - This suggests a file-sharing server is involved, and the initiating account is root.
   - Root access may indicate potential privilege escalation.
 ![](https://i.imgur.com/qu3tsFc.png)
---

### Step 6: Analyze SMB Object List

1. **Download SMB Objects**:
   - Identify two files within the SMB object list. Download them to your Downloads directory for further analysis.

2. **Generate Hashes for Downloaded Files**:
   - Use PowerShell to generate cryptographic hashes (MD5, SHA256, etc.) of the downloaded files.
 ![](https://i.imgur.com/ybBOvcW.png)

### Step 7: Check Files on VirusTotal

1. **Submit Files to VirusTotal:**
   - Upload the downloaded files to [VirusTotal](https://www.virustotal.com) for analysis.
   - **Outcome**: The files are not flagged as malicious by VirusTotal, but they could still be part of a larger attack.
 ![](https://i.imgur.com/qf8Cw2R.png)
![](https://i.imgur.com/NWjMr6M.png)
---

### Step 8: Inspect Files Manually

1. **Open and Inspect Files:**
   - Open the downloaded files in **Notepad** and examine their contents.
   - The files are labeled as “work report for year 2022” and “work report for year 2022,” which appear to be benign but may be decoys designed to mislead.
 ![](https://i.imgur.com/VdGIN7A.png)
---

### Step 9: Investigate HTTP Traffic

1. **Identify HTTP Protocol in Packet 685:**
   - In packet 685, observe the first instance of the HTTP protocol.
   - Follow the HTTP request to check the **URL**, **headers**, and **payload** for any suspicious activity.
 ![](https://i.imgur.com/BNnxKVT.png)
---

### Step 10: Investigate Unfamiliar IP Address

1. **Check IP Address 14.0.0.120:**
   - Investigate the open ports on the unfamiliar IP address **14.0.0.120** by filtering for **SYN-ACK** packets.
   - **Result**: Open ports include:
     - Port 22 (SSH)
     - Port 8080 (HTTP/Apache Tomcat)
     - Port 8009 (AJP)
   - These ports could indicate potential entry points for the attacker.
 ![](https://i.imgur.com/3qHQcKO.png)
---

### Step 11: Analyze HTTP Requests

1. **Analyze GET and POST Requests:**
   - Focus on **POST requests**, which are used to send data to the server. These could indicate malicious activity, such as:
     - File uploads
     - Modifications to server settings
 ![](https://i.imgur.com/YiA4b6O.png)
---

### Step 12: Analyze Suspicious File Signature

1. **Investigate PK File Signature in POST Request:**
   - A **PK file signature** is observed in a POST request. This signature is commonly associated with **ZIP files**.
   - Use **Gary Kesler’s file signature database** to confirm that it corresponds to a ZIP file.
 ![](https://i.imgur.com/Sctekr5.png)
 ![](https://i.imgur.com/E2DKMb5.png)
---

### Step 13: Investigate Tomcat Manager Access

1. **Examine GET Requests to `/manager/html`:**
   - Analyze multiple **GET requests** to the `/manager/html` path, which provides access to the **Tomcat Manager interface**.
   - Identify attempts to gain unauthorized access to this sensitive path, which is key to this attack.
 ![](https://i.imgur.com/4EqVvIC.png)
![](https://i.imgur.com/bP17YST.png)
---

### Step 14: Analyze Authentication and Reverse Shell Command

1. **Successful Authentication Detected:**
   - In packet 20553, the attacker successfully authenticates to the Tomcat Manager using **Base64-encoded credentials**.
   - Decode the credentials using **CyberChef**.

2. **Reverse Shell Command Execution:**
   - After authentication, the attacker sends a **POST request** with a command to establish a **reverse shell**.
   - The reverse shell allows the attacker to execute commands remotely on the compromised server.
 ![](https://i.imgur.com/1FRuKMV.png)
![](https://i.imgur.com/itqC3UZ.png)

---

### Step 15: Track Attacker’s Origin

1. **Track Attacker’s IP Address:**
   - Use the reverse shell connection along with **SYN**, **SYN-ACK**, and **ACK** packets to track the attacker’s IP address.
   - Check the attacker’s IP in **AbuseIPDB** for any previous reports of malicious activities.

2. **Document and Report Findings:**
   - Compile all findings into a detailed report, including:
     - SMB communication indicating potential **privilege escalation**.
     - Exploitation of the **Tomcat Manager** for unauthorized access.
     - The reverse shell command used by the attacker.
     - **Security recommendations** such as:
       - Securing the Tomcat Manager interface.
       - Performing a full **security audit** of the affected systems.
 ![](https://i.imgur.com/9tthYua.png)
![](https://i.imgur.com/3Gburh3.png)
![](https://i.imgur.com/MgMQcXu.png)
![](https://i.imgur.com/y43qf2i.png)



---

## Conclusion

This investigation identifies how a vulnerable **Tomcat Manager interface** was exploited by an attacker to gain unauthorized access to a web server. The detailed steps outlined above provide critical insights into attack patterns and the necessary security measures that need to be taken.

### Security Recommendations
- Restrict access to sensitive server interfaces such as Tomcat Manager.
- Regularly monitor and analyze HTTP traffic for suspicious requests.
- Conduct security audits to identify vulnerabilities in server configurations.




