# How to track (un)signed PowerShell (PS) scripts with Splunk?
This is far from being prod-ready but shoud work as a good prototype to narrow your analysis/reports/hunts. Also, be aware that this **suggests** scripts signed status based on text usually seen from signed PS scripts (any attacker can add it!), it does not guarantee scripts are indeed signed.

> :warning: **Newbie Splunk Hunters:** Running queries using "All Time" can lead to dead indexers/clusters and therefore impact on your relationship with our beloved Splunk admins. Be very careful here!

## Prototype query
```
index=* sourcetype=wineventlog EventCode=4104 ScriptBlock_ID=* Path=*

| eval Message=replace(Message, "[\r\n]+", "")

| eval blocks=replace(Message,".*Creating Scriptblock text \(\d+ of (\d+)\).*", "\1")

| stats values(Message) AS script BY Path, ScriptBlock_ID, host, blkcount

| eval signed=if(NOT match(script, "#\s+(SIG|Begin signature block)") AND (blkcount=mvcount(script)), 0, 1)

| stats values(Path) AS script BY host, signed
```
