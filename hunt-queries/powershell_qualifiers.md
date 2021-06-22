# How to detect suspicious PowerShell activity with Splunk?
The following SPL snippet comes from one of the [Splunk Hyper Queries](https://ateixei.medium.com/siem-hyper-queries-introduction-current-detection-methods-part-i-ii-13330b5137df) I use to score/rate suspicious endpoint sessions. Most of the checks are done using [eval's match()](https://docs.splunk.com/Documentation/SCS/current/SearchReference/ConditionalFunctions#match.28.26lt.3Bstr.26gt.3B.2C_.26lt.3Bregex.26gt.3B.29) and they can be applied to pretty much any endpoint telemetry, including EDR, Sysmon (EID 1) and Windows 4688/4104 log events.

The idea is to quickly share some real-life SPL with the Splunk Detection Engineering community. Have fun and don't forget to refer to author/references below if using these ideas/code somewhere. Feedback always welcome!

![image](https://user-images.githubusercontent.com/14159692/122783727-1bf53b00-d2b2-11eb-8ccf-5049d1b3129e.png)

## A few notes

- Some checks rely on long regex strings aiming to detect a wide range of activities, you may want to split those into smaller subsets for your environment for easier maintenance and fine-grained scoring.
- While some of those checks indicate very suspicious activity, relying on atomic indicators is by far what contributes towards high alert volume  and low signal-to-noise.
- Of course, depending on how PowerShell is used within an environment, those may require some initial exception handling/baseline analysis until the noise is reduced to a manageable amount.
- The single score related to each qualifier must be fine-tuned for each environment. You can extract and calculate scores later via [eval's mvfilter()](https://docs.splunk.com/Documentation/Splunk/8.2.0/SearchReference/MultivalueEvalFunctions#mvfilter.28X.29) and [eventstats](https://docs.splunk.com/Documentation/Splunk/8.2.0/SearchReference/Eventstats) sum() and median().

# SPL: PowerShell qualifiers (indicators/observables)
The idea here is to accumulate the *qualifier*, the score for each qualifier and the commandline/log matched and later calculate an overall score/severity range which will either generate an alert or populate a Threat Hunting Leads Dashboard, more details on the scoring system will be available from the blog series linked above.

Basically, scores higher than 5 are considered strong indicators (highlighted in the landing/hunting dashboard) while anything below 3 are basically observables (I'm not writing a Scientific paper for this!).

```
| eval _comment="At this poiint, field ps_command should hold PowerShell related command lines (one-liners, script blocks)"
| eval _comment="Field ParentPath and ChildPath should hold the parent and child process full/absolute paths"

| eval _comment="Some sanitization"
| eval ps_command=replace(ps_command, "[\r\n]", "")
| eval ps_command=replace(ps_command, "\S+\\\(pwsh|sqlps|sqltoolsps|powershell)\.exe|^(pwsh|sqlps|sqltoolsps|powershell)(\.exe)*", "")
 
| eval obf_symbol=ps_command
| makemv tokenizer="(['@%^,;:=&+\"\(\{\)\}`!\*\./\?_\[\]\|<>~$])" obf_symbol
| eval obf_symbol_count=mvcount(obf_symbol)
| eval nonobf_symbol=replace(ps_command, "\s", "")
| makemv tokenizer="([^'@%^,;:=&+\"\(\{\)\}`!\*\./\?_\[\]\|<>~$])" nonobf_symbol
| eval nonobf_symbol_count=mvcount(nonobf_symbol)

| eval ps_len=len(ps_command)
| eval ratio=(nonobf_symbol_count/obf_symbol_count)

| eval _comment="The following are loaded as regex strings via !match() statements. I usually load those from lookups but listed here for siimplicity."
| eval ps_command_exception_regex="REGEX_HERE" 
| eval ps_parent_exception_regex="REGEX_HERE"

| eval qualifier="PS: Highly obfuscated command (ratio: ".ratio." ps_len: ".ps_len.")", qualifiers=if(ps_len>100 AND ratio<3, mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 9", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Suspicious cmdlet", qualifiers=if(match(ps_command, "(?i)Add-Exfiltration|Add-Persistence|Add-RegBackdoor|Add-ScrnSaveBackdoor|Check-VM|Do-Exfiltration|Enabled-DuplicateToken|Exploit-Jboss|Find-Fruit|Find-GPOLocation|Find-TrustedDocuments|Get-ApplicationHost|Get-ChromeDump|Get-ClipboardContents|Get-FoxDump|Get-GPPPassword|Get-IndexedItem|Get-Keystrokes|LSASecret|Get-PassHash|Get-RegAlwaysInstallElevated|Get-RegAutoLogon|Get-RickAstley|Get-Screenshot|Get-SecurityPackages|Get-ServiceFilePermission|Get-ServicePermission|Get-ServiceUnquoted|Get-SiteListPassword|Get-System|Get-TimedScreenshot|Get-UnattendedInstallFile|Get-Unconstrained|Get-VaultCredential|Get-VulnAutoRun|Get-VulnSchTask|Gupt-Backdoor|HTTP-Login|Install-SSP|Install-ServiceBinary|Invoke-ACLScanner|Invoke-ADSBackdoor|Invoke-ARPScan|Invoke-AllChecks|Invoke-BackdoorLNK|Invoke-BypassUAC|Invoke-CredentialInjection|Invoke-DCSync|Invoke-DllInjection|Invoke-DowngradeAccount|Invoke-EgressCheck|Invoke-Inveigh|Invoke-InveighRelay|Invoke-Mimikatz|Invoke-Mimikittenz|Invoke-NetRipper|Invoke-NinjaCopy|Invoke-PSInject|Invoke-Paranoia|Invoke-PortScan|Invoke-PoshRat|Invoke-PostExfil|Invoke-PowerDump|Invoke-PowerShellTCP|Invoke-PowerShellWMI|Invoke-PsExec|Invoke-PsUaCme|Invoke-ReflectivePEInjection|Invoke-ReverseDNSLookup|Invoke-RunAs|Invoke-SMBScanner|Invoke-SSHCommand|Invoke-Service|Invoke-Shellcode|Invoke-Tater|Invoke-ThunderStruck|Invoke-Token|Invoke-UserHunter|Invoke-VoiceTroll|Invoke-WScriptBypassUAC|Invoke-WinEnum|Invoke-WmiCommand|MailRaider|New-HoneyHash|Out-Minidump|Port-Scan|PowerBreach|PowerUp|PowerView|Remove-Update|Set-MacAttribute|Set-Wallpaper|Show-TargetScreen|Start-CaptureServer|VolumeShadowCopyTools|NEEEEWWW|(Computer|User)Property|CachedRDPConnection|get-net\S+|invoke-\S+hunter|Install-Service|get-\S+(credent|password)|remoteps|Kerberos.*(policy|ticket)|netfirewall|Uninstall-Windows|Verb\s+Runas|AmsiBypass|nishang|Invoke-Interceptor|EXEonRemote|NetworkRelay|PowerShelludp|PowerShellIcmp|CreateShortcut|copy-vss|invoke-dll|invoke-mass|out-shortcut|Invoke-ShellCommand") AND !match(ps_command, ps_command_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 8", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Web Client traces", qualifiers=if(match(ps_command, "(?i)(iex|[\.-]webclient|WebRequest|Net\.Socket|InternetExplorer.Application|XmlHttp)") AND !match(ps_command, "(?i)".ps_command_exception_regex) AND !match(ParentPath, "(?i)".ps_parent_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 8", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: System.Mgt usage", qualifiers=if(match(ps_command, "(?i)(system\.management\.automation)") AND !match(ParentPath, "(?i)".ps_parent_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 7", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Highly suspicious keywords", qualifiers=if(match(ps_command, "(?i)(bitstransfer|mimik|metasp|AssemblyBuilderAccess|Reflection\.Assembly|shellcode|injection|cnvert|shell\.application|start-process|FromBase64String|Rc4ByteStream|System\.Security\.Cryptography|lsass\.exe|localadmin|LastLoggedOn|hijack|BackupPrivilege|ngrok|comsvcs|backdoor|brute.?force|Port.?Scan|Exfiltration|exploit|DisableRealtimeMonitoring|beacon)"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 7", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Download reference", qualifiers=if(match(ps_command, "(?i)[^\\\]download") AND !match(ps_command, "(?i)".ps_command_exception_regex) AND !match(ParentPath, "(?i)".ps_parent_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Script reference", qualifiers=if(match(ps_command, "(?i)\.(vbs)|wscript|javascript") AND !match(ParentPath, "(?i)".ps_parent_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: WMI usage", qualifiers=if(match(ps_command, "(?i)(wmiobject|WMIMethod|RemoteWMI|PowerShellWmi|wmicommand)") AND !match(ParentPath, "(?i)".ps_parent_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Potential long base64 string", qualifiers=if(match(ps_command, "(?i)[a-z0-9+/=]{60}"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Overly long command", qualifiers=if(ps_len>320 AND ratio>48, mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 5", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Nested LOLBin", qualifiers=if(match(ps_command, "(?i)(rundll32|regsvr32|cmd)\.exe"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: HTTP/S/FTP usage", qualifiers=if(match(ps_command, "(?i)(https*|ftp):") AND !match(ps_command, "(?i)".ps_command_exception_regex) AND !match(ParentPath, "(?i)".ps_parent_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Eventlog manipulation", qualifiers=if(match(ps_command, "(?i)(eventlog|\.evtx)"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Fairly suspicious keywords", qualifiers=if(match(ps_command, "(?i)(token|password|dump|Obfuscation|sploit|scanner|rundll|Reflection|Invoke-Command|base64|discover-|github)") AND !match(ps_command, "(?i)".ps_command_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 3", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Invoke command", qualifiers=if(match(ps_command, "(?i)(invoke[-])") AND !match(ParentPath, "(?i)".ps_parent_exception_regex) AND !match(ps_command, "(?i)".ps_command_exception_regex), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 2", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: EncodedCommand", qualifiers=if(match(ps_command, "(?i)[-]e(nc*o*d*e*d*c*o*m*m*a*n*d*)*\s+[^-]"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 2", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Potential Downgrade Attack", qualifiers=if(match(ps_command, "(?i)([-]ve*r*s*i*o*n*\s+2)"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Suspicious [char] usage", qualifiers=if(match(ps_command, "(?i)(convert|byte|length|xor|substring|join|toint|tostr)*\[char\](convert|byte|length|xor|substring|join|toint|tostr)*"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 6", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Service Manipulation", qualifiers=if(match(ps_command, "(?i)(new|set)-service"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 8", cmdlines." (".qualifier.")"), qualifiers)

| eval qualifier="PS: Task Manipulation", qualifiers=if(match(ps_command, "(?i)ScheduledTask"), mvappend(qualifiers, "[".session_label."] ".qualifier." # score: 8", cmdlines." (".qualifier.")"), qualifiers)

| eval _comment="Consider scoring if a non-traditional PowerShell program/child path is used (pwsh|sqlps|sqltoolsps), depending on how PS is used in the target environment"
```
## What can be done next?
You may perform the following checks not covered here, mainly around anomaly detection/baseline analysis for a more robust, less FP-prone detection:

- Is the command making reference to a new script (ps1/psd1/etc) NOT seen before (baseline)?
- Is the command length higher than X and NOT part of the baseline?
- Is the command executed from a parent NOT part of the baseline?

For creating the baseline, no fancy machine learning needed, simply stack counting via stats command, saving results to a MV-field enabled lookup which is consumed by yet another qualifier check (detection component/feature).

# References

  - https://github.com/samratashok/nishang

  - https://github.com/secprentice/PowerShellWatchlist/blob/master/badshell.txt

  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_malicious_commandlets.yml

  - https://www.blackhat.com/docs/us-17/thursday/us-17-Bohannon-Revoke-Obfuscation-PowerShell-Obfuscation-Detection-And%20Evasion-Using-Science-wp.pdf

  - https://arxiv.org/pdf/1804.04177.pdf (I just leveraged the Symbols analysis from this one)
