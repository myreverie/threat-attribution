import re
text = """Resource Development	T1583.003	Acquire Infrastructure: Virtual Private Server	POLONIUM has acquired various servers for C&C and also for storing exfiltrated files.
T1587.001	Develop Capabilities: Malware	POLONIUM has developed at least six backdoors and several other malicious modules.
T1588.001	Obtain Capabilities: Malware	POLONIUM has used a publicly available keylogger.
Execution	T1059.001	Command and Scripting Interpreter: PowerShell	POLONIUM has used the CreepySnail and CreepyDrive PowerShell backdoors in their attacks.
T1059.003	Command and Scripting Interpreter: Windows Command Shell	DeepCreep, MegaCreep, FlipCreep and TechnoCreep use cmd.exei to execute commands in a compromised computer.
T1129	Shared Modules	DeepCreep and MegaCreep have their code divided into small DLLs, which are loaded both statically and dynamically.
Persistence	T1547.009	Boot or Logon Autostart Execution: Shortcut Modification	POLONIUM’s backdoors persist by writing shortcuts to the Windows Startup folder.
T1053.005	Scheduled Task/Job: Scheduled Task	DeepCreep, MegaCreep and FlipCreep create scheduled tasks for persistence.
Defense Evasion	T1140	Deobfuscate/Decode Files or Information	DeepCreep and MegaDeep use AES encryption to obfuscate commands and login credentials stored in local files on the victim’s computer.
T1070.004	Indicator Removal on Host: File Deletion	POLONIUM’s exfiltration modules delete screenshot files or keystroke logs from a compromised host after they are exfiltrated.
T1036.005	Masquerading: Match Legitimate Name or Location	POLONIUM has used filenames such as Mega.exei or DropBox.exei for its backdoors, to make them look like legitimate binaries.
T1218.004	System Binary Proxy Execution: InstallUtil	POLONIUM has used InstallUtil.exei to execute DeepCreep.
T1083	File and Directory Discovery	POLONIUM’s custom exfiltrator module builds a listing of files for any given folder.
T1057	Process Discovery	DeepCreep, MegaCreep and FlipCreep look for running processes and kill other instances of themselves.
T1082	System Information Discovery	TechnoCreep and POLONIUM’s reverse shell module send information such as computer name, username, and operating system to a remote server, in order to identify their victims.
T1016	System Network Configuration Discovery	TechnoCreep sends a list of IP addresses associated with a victim’s computer.
T1033	System Owner/User Discovery	POLONIUM has executed whoami.exei to identify the logged-on user.
Collection	T1560.002	Archive Collected Data: Archive via Library	DeepCreep, MegaCreep and FlipCreep use .NET’s ZipFile class to archive collected data.
T1115	Clipboard Data	POLONIUM’s custom keylogger retrieves clipboard data from compromised computers.
T1005	Data from Local System	POLONIUM’s exfiltrator module collects files from a compromised system.
T1056.001	Input Capture: Keylogging	POLONIUM has used custom and publicly available keyloggers.
T1113	Screen Capture	POLONIUM has used custom modules for taking screenshots.
T1125	Video Capture	POLONIUM has used a custom module to capture images using the compromised computer’s webcam.
Command and Control	T1071.001	Application Layer Protocol: Web Protocols	CreepySnail and POLONIUM’s file exfiltrator modules use HTTP communication with the C&C server.
T1071.002	Application Layer Protocol: File Transfer Protocols	FlipCreep and POLONIUM’s file exfiltrator modules use FTP communication with the C&C server.
T1132.001	Data Encoding: Standard Encoding	CreepySnail, CreepyDrive and some of POLONIUM’s reverse shell modules use base64-encoded commands to communicate with the C&C server.
T1573.001	Encrypted Channel: Symmetric Cryptography	DeepCreep and MegaCreep AES encrypt commands and their output.
T1095	Non-Application Layer Protocol	TechnoCreep and POLONIUM’s reverse shell module use TCP.
T1571	Non-Standard Port	POLONIUM has used non-standard ports, such as 5055 or 63047, for HTTP.
T1572	Protocol Tunneling	POLONIUM’s tunnels module uses the Plink utility to create SSH tunnels.
T1102.002	Web Service: Bidirectional Communication	POLONIUM has used cloud platforms such as OneDrive, Dropbox, and Mega to send commands and store the output.
Exfiltration	T1041	Exfiltration Over C2 Channel	DeepCreep, MegaCreep, FlipCreep and TechnoCreep exfiltrate files over the C&C channel via uploadi commands.
T1567.002	Exfiltration Over Web Service: Exfiltration to Cloud Storage	POLONIUM has used OneDrive, Dropbox, and Mega cloud storage to store stolen information."""

technique_re = r'T1{1}[0-9]{3}(?:.[0-9]{3}){0,1}'
results = re.findall(technique_re, text)


print(len(results))
technique_set = set()
for result in results:
    technique_set.add(result.strip('.'))
print(technique_set)