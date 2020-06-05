Blog post here: https://opstune.com/2020/06/05/spl-nuggets-know-your-admins-from-eventlogs/
```
index=botsv3 sourcetype=wineventlog earliest=0 ((EventCode=4688 Token_Elevation_Type IN ("*(2)","*1937")) OR (EventCode=4624 Elevated_Token=Yes))

NOT (
  Account_Name="system" OR 
  (Account_Name="dwm-*" Process_Name="c:\\windows\\system32\\winlogon.exe") OR
  (Security_ID IN ("* service","nt *","iis *") Process_Name IN ("c:\\windows\\system32\\services.exe","c:\\windows\\system32\\svchost.exe"))
)

| eval _comment="The following 4 lines must be turned into a macro for cleaner code and is meant to be a general user &amp; domain info normalization routine. In production, consider using lower/trim and adjusting idx per eventcode"
| eval idx=if(mvindex(Account_Name,1)="-", 0, 1)
| eval user=mvindex(Account_Name,idx)
| eval idx=if(mvindex(Account_Domain,1)="-", 0, 1)
| eval domain=mvindex(Account_Domain,idx)

| eval proc=lower(coalesce(New_Process_Name, Process_Name))
| where NOT (user="-"OR (proc="-" AND match(user,"\$$")))
| eval host=lower(host)

| stats values(host) AS hosts, values(proc) AS process, sparkline, count, max(_time) AS LastSeen
  BY user, domain

| eval _comment="Consider enriching accounts here and filtering known/expected out (more details below)"

| eval process=if(mvcount(process)>10, mvappend("Truncated at 10 entries (".mvcount(process)." total):", mvindex(process,0,9)), process)
| eval hosts=if(mvcount(hosts)>10, mvappend("Truncated at 10 entries (".mvcount(hosts)." total):", mvindex(hosts,0,9)), hosts)

| eval LastSeen=strftime(LastSeen, "%F")
| eval user=domain."\\".user
| fields - domain
| sort 0 -num(count)
```
