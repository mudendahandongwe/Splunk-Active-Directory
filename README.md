# Splunk, Active Directory & Atomic Red Team Lab

Instructional videos for this project can be found in a 5-part series on the <a href = "https://www.youtube.com/@MyDFIR">MyDFIR YouTube channel</a>. The video for part 1 is <a href = "https://www.youtube.com/watch?v=5OessbOgyEo&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=13"> here</a>. 

This project was done using VirtualBox and 4 virtual machines in a NAT network. The main components of the project are:
- Windows Server 2022 (AD-DC10)
  - Install Active Directory services on a Windows 2022 server and create users.
  - Install and configure Splunk Universal Forwarder.
  - Install and configure Sysmon to forward events to Splunk.
- Splunk Server
  - Install and configure Splunk to receive logs from the Windows server and Windows workstation.
  - Use Splunk to identify attacks in forwarded logs.
- Windows 10 Workstation (Target-PC)
  - Add the Windows 10 workstation to the Active Directory domain.
  - Install and configure Splunk Universal Forwarder.
  - Install and configure Sysmon to forward events to Splunk.
  - Install Atomic Red Team to simulate MITRE ATT&CK techniques.
- Kali Linux
  - Conduct brute force attack on Windows 10 workstation using Crowbar.

## Network Topology

![image](https://github.com/user-attachments/assets/13e6646d-e830-487e-b499-af6f4b548cbb)

## Project Highlights

### Splunk Server

Splunk was installed and configured on a VM running Ubuntu Server 24.04.1. A static IP of 10.0.10.10 was set by modifying the /etc/netplan/50-cloud-init.yaml file. NOTE: Indentations in the yaml file are important!

![image](https://github.com/user-attachments/assets/cb062583-c9ab-4cc9-b6dd-a8ea7624ae40)

The static IP address is applied to the server:

![image](https://github.com/user-attachments/assets/6577b496-4ac2-46f4-821c-6c0d8f072b0a)

Splunk was configured to listen on port 9997 and the Splunk interface to be accessed via a web browser at 10.0.10.10 on port 8000. An "endpoint" index was created to receive logs forwarded from the Active Directory server and the Windows workstation.

![image](https://github.com/user-attachments/assets/b45d2a65-addc-45c8-8c39-63e69950bc8b)



### Active Directory Server
Active Directory services were installed and a domain created (lab.local). A "Workstations" organizational unit was created and the Windows 10 workstation added to it.

![image](https://github.com/user-attachments/assets/b56fad45-ac03-4667-b439-9df2b56c34cc)

Organizational units were created for IT and HR and two users added to each unit.

![image](https://github.com/user-attachments/assets/8d8d0250-283f-402a-b5bd-87b3bead550d)

### Kali Linux Brute Force Attack

RDP was enabled on the Windows 10 workstation and from Kali Linux a brute force attack was conducted against the Windows 10 workstation using <a href = "https://www.kali.org/tools/crowbar/"> Crowbar</a>. The attack targeted the user Mary Weaver (mweaver). Twenty passwords were extracted to passwords.txt from the rockyou.txt passwords list and used as the list for the brute force attack. In order to register a successful attack, Mary Weaver's password was added to passwords.txt. 

![image](https://github.com/user-attachments/assets/0bd61a38-c7e5-4a9a-8348-1fdb49e49b89)


Splunk registered 23 events related to mweaver:

![image](https://github.com/user-attachments/assets/b9bfdbdd-ad08-42e9-92f1-9e86345e0a00)

Windows event <a href = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625"> code 4625</a> is for failed logon attempts. Splunk recorded 20 failed login attemtps for mweaver's account, which is the number of incorrect passwords contained in the passwords.txt file:

![image](https://github.com/user-attachments/assets/ecacce7e-251e-4966-8528-3b8c98ab480e)

### Atomic Red Team Simulated Attacks

<a href = "https://www.atomicredteam.io/">Atomic Red Team</a> is a library of simple, focused tests mapped to the <a href = "https://attack.mitre.org/">MITRE ATT&CK matrix</a>. It is typically used to test whether an organization's security controls are detecting attacks.

In this lab, Atomic Red Team was installed on the Winodws 10 workstation and a couple of attacks run and detected in Splunk.

#### Create Local Account (T1136.001)

One technique attackers use to establish persistence on a compromised host is to create new local accounts. This technique, T1136.001 in the MITRE framework, is described <a href = "https://attack.mitre.org/techniques/T1136/001/">here</a>. The Atomic Red Team <a href = "https://www.atomicredteam.io/atomic-red-team/atomics/T1136.001">simulates this technique</a> in various ways, depending on the system and OS. In this lab, Atomic Red Team used "NewLocalUser" as the account to be created:

![image](https://github.com/user-attachments/assets/5ca9d06d-8539-4a3e-aa3b-83f6f0c40436)

We can see this event recorded in Splunk:

![image](https://github.com/user-attachments/assets/d035c83d-5229-421a-95ee-cac71037fa77)

#### File and Directory Permissions Modification (T1222.001)

In order to evade access control lists and access protected files, attackers may attempt to modify file or directory permissions. MITRE describes this technique (T1222.001) <a href = "https://attack.mitre.org/techniques/T1222/001/">here</a>.

In the Atomic Red Team simulation, one of the files which it attempts to modify is T1222.001_attrib as seen here:

![image](https://github.com/user-attachments/assets/01f917b5-b902-4b5c-a038-b0c7ba6c273b)

If we search for this string in Splunk, we can identify the events:

![image](https://github.com/user-attachments/assets/96b078a4-9644-4d51-9104-f1a7efa53264)
