# blacksun_tabletop
## Using Splunk with Sysmon logs to track BlackSun ransomware. A practice exercise for learning to better use Splunk and map IOCs to the Mitre Att&ck framework.

This challenge originally comes from tryhackme and is an exercise in tracking how BlackSun ransomware might be introduced to a system and used to encrypt and hold files for ransom.

This writeup & exercise is an attempt to better learn Splunk searching, the IOCs of common ransomware & how to map IOCs to the Mitre Att&ck framework.

### Resources
- [VMWare](https://blogs.vmware.com/security/2022/01/blacksun-ransomware-the-dark-side-of-powershell.html)
- [VirusTotal](https://www.virustotal.com/gui/file/e5429f2e44990b3d4e249c566fbf19741e671c0e40b809f87248d9ec9114bef9/community)
- [TryHackMe](https://tryhackme.com/room/posheclipse) 

### Exercise Scenario
- We have been asked to investigate some events that occurred on a machine. Some strange file extensions have been noticed and we are concerned ransomware may have been introduced to the system.

![blacksunnn](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/f84c0f08-6ca9-437d-a204-48770e960a25)

### Pre
Before we begin our searches, let's see what source types we have available to us. Seems we have around 7k Sysmon logs available to us which is a great place to start. See the [sysmon reference guide](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) for common event codes.
> search & reporting > data summary > sourcetypes

![0-0setup-sourcetype](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/26a187bf-d5c7-4c21-94ec-af1f451af1c9)

### 1
We are prompted to locate a suspicious binary. Let's filter for EventCode="3" to check for network connections. We can then look under the Image field to see if any suspicious or abornmal binaries/executables stand out. Our standout executable is pretty clear in this case.
> index="main" EventCode=3

![1-1result](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/2f630708-a6bc-42c8-80e6-c0c8ece13f54)

### 1-2
Let's dive a little more into these other binaries. We know powershell and onedrive. But we should pay special attention to mpcmdrun. This isn't an instantly noticable binary at least for me. It is a command line tool to manage microsoft defender. After some searching, it seems that some malware may attempt to mimic this binary. [source](https://malwaretips.com/blogs/mpcmdrun-exe-what-it-is-should-i-remove-it/) We are fortunate enough to have the RuleName field mapped to Mitre ATT&CK techniques and we can see that we have a hit on technique id T1036 Masquerading. [source](https://attack.mitre.org/techniques/T1036/) Out of curiousity, I would like to see how many other binaries this suspicious executable is mimicing.
> index="main" RuleName="technique_id=T1036,technique_name=Masquerading"

![1-2result](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/fa6b3d1d-cbcc-4b52-b0b4-0b0ddb238704)

### 2
Let's try to find where this binary was downloaded from. We can start by filtering by DestinationPort. There are three events involving port 80 so lets start there. I will further filter to only see DestinationPort="80". Under the Image field, we can see that powershell was used. Checking RuleName again will also give us the associated Mitre technique (T1059.1 - powershell). By doing a little more digging we can find where the binary was downloaded from.
> index="main" DestinationPort="80"

![2-1resultports](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/3ba751f2-77cf-4ec2-82f9-a2b28346955d)
![2-2resultpowershell](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/54cf475a-765a-45ef-aedb-923ae447116a)


### 2-2
Filtering by the powershell image we can view the CommandLine field which is extremely helpful to see what commands were run. One result stands out as very suspicious. Encoded commands can be an indicator of an attacker trying to cover their tracks.

![2-3resultscommandline](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/6aa61a64-4686-4209-9988-1257883a831b)

Let's decrypt what we found using [Cyberchef](https://gchq.github.io/CyberChef/) We can see now how and where the attacker got the binary as well as the outfile.

![2-5resultsdecoded2](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/d8703fc4-8fe1-476e-97e3-eab1da1ae2a8)

### 3
There is more to the command that was run however. The attacker creates a new task and schedules it to run as SYSTEM which we know is the highest priveleged account. Finally the attacker runs the tasks. [schtasks documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
```
wget - downloads the file from the source
outfile - dictates where the file is saved
schtasks - schedules a task to run at a specific time, the task in this case is the binary being executed.
/CREATE to create a new task
/TN <task_name>
/TR <task_to_run>
/SC <schedule_type>
/EC <channel_name> (for ONEVENT trigger)
/MO <modifiers>
/RU <domain_user/system>
/f supress warnings
/RUN <task_name>
```
### 4
The above binary then connected to a remote server. We can locate this address by again filtering by the Image and looking under the QueryName field.
> index="main" Image="C:\\Windows\\Temp\\OUTSTANDING_GUTTER.exe" QueryName=*

![4-1resultsquery](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/85e5ba5a-146f-4f86-978e-f09c5f0cfc0e)

This field would usually show the search term used in a browser. In fact, we can see some typical benign traffic if we filter QueryName only from chrome.exe.
> index="main" QueryName=* Image="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"

![4-2resultsbenigntraffichrome](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/87c0c842-ad74-4ac4-abb5-58fb33653b51)

### 5
We are now directed to find a powershell script that was downloaded to the same location as the suspicious binary we found earlier. We know the binary is located in C:\Windows\Temp so lets run a search for *.ps1 and see if we find any powershell scripts there. Sure enough, the first result is what we are after.
> index="main" *.ps1

![5-1resultsscripts](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/f7d6381b-c943-46a7-a59f-ae42808898a1)

### 6
Seeing as the file hashes are available to us, now would be a good time to grab one and run it through [virustotal](https://www.virustotal.com/gui/home/search). The file is indeed flagged as malicious and seems to be black sun ransomware.

![6-1virustotalblacksun](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/98c0843b-c427-47b0-9250-84c0f8792b64)

### 7
Knowing we have some common ransomware on the system, we should probably look for a ransom note of some sort. In this exercise we can easily find that by searching for the ransomware name or simply *.txt.
> index="main" *.txt

![7-1resultsreadme](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/b12b3e48-fc33-4dc4-a409-eb9571b92cca)

### 8
In this exercise an image was also created. We can filter by common image file types or, again, the name of the ransomware "blacksun" to locate it.
> index="main" blacksun

![8-1resultsimage](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/cc8203b1-bc36-40d0-9bca-dce8d1b53ff8)

### Integrating IOCs w/ the MITRE ATT&CK Framework. 
In this exercise & the associated logs, we were fortunate enough to have the IOCs mapped to MITRE techniques within Splunk. Utilizing this information I built an Enterprise ATT&CK Matrix for BlackSun ransomeware.

![blacksun_ransomware](https://github.com/jamesryla/blacksun_tabletop/assets/58945104/ce61704f-b371-42ce-a9e6-3fa9ae740d45)


  
