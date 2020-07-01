Blog post here: https://opstune.com/2020/07/01/spl-nuggets-visualizing-rdp-ts-connections-from-eventlogs/
```
index=* sourcetype=WinEventLog EventCode=4648 TERMSRV Additional_Information=termsrv* 

| eval src_user=lower(trim(mvindex(Account_Name,0)))
| eval dest_user=lower(trim(mvindex(Account_Name,1)))
| eval host=lower(trim(replace(host, "\..+", "")))
| eval dest_nt_host=lower(trim(replace(dest_nt_host, "\..+", "")))

| dedup 1 src_user host dest_user dest_nt_host

| eval src_user__dest_user=src_user."->".dest_user

| appendpipe [ | stats count AS sessions BY host src_user__dest_user | rename host AS source, src_user__dest_user AS target ]
| appendpipe [ | stats count AS sessions BY src_user__dest_user dest_nt_host | rename src_user__dest_user AS source, dest_nt_host AS target ]

| where sessions>0

| table source target sessions
```
