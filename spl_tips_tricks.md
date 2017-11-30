# Splunk Processing Langage (SPL) tips and tricks
Here you can find interesting usages and approaches for crafting better, reliable queries basically by checking some real-life examples. Feel free to suggest a topic/command to be listed here.

## **Command:** makeresults
I usually make use of `makeresults` command in two situations:
### When I want to check SH's clock value
This is particulary useful when I want to trigger an action (alert, notable) from a saved search within the next 2 minutes. Simply schedule the search to run a couple of minutes after the time seen in the output of this command:
```
| makeresults
```
The value for *_time* is exactly the SH's clock time.

### When I need to quickly validade some SPL code
For instance, I typically build some sample data (without touching the indexers) to play with and later come to a conclusion on how the code will behave. For instance, here's how to create a multi-value field and later count the number of entries in it:
```
| makeresults
| eval mvfield="this is a multi value field"
| eval mvfield=split(mvfield, " ")
| eval entries=mvcount(mvfield)
```
**Reference**: http://docs.splunk.com/Documentation/Splunk/7.0.0/SearchReference/Makeresults

## **How to correlate parent/child processes from 4688 Eventlog**
[Unlike *sysmon*](#a2), Windows hosts before 10/2016 versions do not provide the parent process name but the process ID only within event 4688 (New Process Created) contents - which is an important piece for threat hunting. Therefore, you need to do some correlation in order to address that.

There are many ways to do it (supporting lookups, summary index, etc), but here's one approach leveraging `streamstats` command assuming you are interestd in child processes being spawned within 60 seconds after the parent instance which is far from 100% coverage but already reveals many interesting scenarios. To increase/decrease this time span, simple tweak the *time_window* parameter below:
```
EventCode=4688
| table _time ComputerName New_Process_Name New_Process_ID Creator_Process_ID
| eval proc_name_id_all=New_Process_Name."#mysep#".New_Process_ID
| sort 0 + _time
| streamstats time_window=60s values(proc_name_id_all) AS proc_name_id_all by ComputerName
| eval parent=mvfind(proc_name_id_all, "#mysep#".Creator_Process_ID."$")
| eval parent=replace(mvindex(proc_name_id_all,parent), "^(.+)#mysep#.+$", "\1")
```

Note that the `table` command is just used to demonstrate the approach (prototype) and quickly display relevant fields. Consider optimizing this query before using in production. Thanks Martin Müller for helping with ideas/suggestions.

**References:**
- https://docs.microsoft.com/en-us/windows/device-security/auditing/event-4688
- http://docs.splunk.com/Documentation/Splunk/7.0.0/SearchReference/Streamstats
