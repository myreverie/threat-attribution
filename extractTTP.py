import re
text = """Network Connection Enumeration

T0840

Adversaries may perform network connection enumeration to discover information about device communication patterns.

Data Obfuscation

T1001

Adversaries may obfuscate command and control traffic to make it more difficult to detect.

Protocol Impersonation

T1001.003

Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts.

OS Credential Dumping

T1003

Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.

Rootkit

T1014

Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.

Obfuscated Files or Information

T1027

Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.

Software Packing

T1027.002

Adversaries may perform software packing or virtual machine software protection to conceal their code.

Masquerading

T1036

Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.

Network Sniffing

T1040

Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.

Network Service Discovery

T1046

Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.

Dynamic-link Library Injection

T1055.001

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges.

Keylogging

T1056.001

Adversaries may log user keystrokes to intercept credentials as the user types them.

PowerShell

T1059.001

Adversaries may abuse PowerShell commands and scripts for execution.

Application Layer Protocol

T1071

Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.

Web Protocols

T1071.001

Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.

Mail Protocols

T1071.003

Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic.

DNS

T1071.004

Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.

Data Staged

T1074

Adversaries may stage collected data in a central location or directory prior to Exfiltration.

Valid Accounts

T1078

Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

File and Directory Discovery

T1083

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.

Multi-hop Proxy

T1090.003

To disguise the source of malicious traffic, adversaries may chain together multiple proxies.

Non-Application Layer Protocol

T1095

Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network.

Multi-Stage Channels

T1104

Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions.

Native API

T1106

Adversaries may interact with the native OS application programming interface (API) to execute behaviors.

Modify Registry

T1112

Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.

Automated Collection

T1119

Once established within a system or network, an adversary may use automated techniques for collecting internal data.

Data Encoding

T1132

Adversaries may encode data to make the content of command and control traffic more difficult to detect.

Non-Standard Encoding

T1132.002

Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect.

Network Share Discovery

T1135

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement.

Deobfuscate/Decode Files or Information

T1140

Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.

Exploit Public-Facing Application

T1190

Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.

Domain Trust Discovery

T1482

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments.

Installer Packages

T1546.016

Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content.

Dynamic Linker Hijacking

T1547.006

Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries.

Inter-Process Communication

T1559

Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution.

Archive Collected Data

T1560.003

An adversary may compress and/or encrypt data that is collected prior to exfiltration.

Hide Artifacts

T1564

Adversaries may attempt to hide artifacts associated with their behaviors to evade detection.

Service Execution

T1569.002

Adversaries may abuse the Windows service control manager to execute malicious commands or payloads.

Lateral Tool Transfer

T1570

Adversaries may transfer tools or other files between systems in a compromised environment.

Protocol Tunneling

T1572

Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems.

Encrypted Channel

T1573

Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

Symmetric Cryptography

T1573.001

Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

Asymmetric Cryptography

T1573.002

Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

DLL Side-Loading

T1574.002

Adversaries may execute their own malicious payloads by side-loading DLLs.

Compromise Infrastructure

T1584

Adversaries may compromise third-party infrastructure that can be used during targeting.

Malware

T1587.001

Adversaries may develop malware and malware components that can be used during targeting.

Obtain Capabilities

T1588

Adversaries may buy and/or steal capabilities that can be used during targeting.

Stage Capabilities

T1608

Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting.

Deploy Container

T1610

Adversaries may deploy a container into an environment to facilitate execution or evade defenses."""

technique_re = r'T1{1}[0-9]{3}(?:.[0-9]{3}){0,1}'
results = re.findall(technique_re, text)


print(len(results))
technique_set = set()
for result in results:
    technique_set.add(result.strip('.'))
print(technique_set)