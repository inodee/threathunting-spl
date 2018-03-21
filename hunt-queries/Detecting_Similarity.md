# Why monitoring for similarities within a list of processes?
Well, to begin with, attackers may try to disguise their processes with names very similar to the ones usually found on a default installation of an operating system.

In case of Windows, take *svchost.exe* as an example. Process names like *msvchost.exe* or *svch0st.exe* may be overlooked during a quick analysis. Besides that, typos, half-baked code or any negligence from an attacker may lead to this scenario, hence the need to monitor for it given the cost (of implementing) and the benefit (of spotting) it.

## How to do that with Splunk?
There are many ways to do it (Clustering/ML?), but here we simply make use an implementation of [Levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance).

Basically, pick an implementation of the concept in form of an algorithm, provide as input a pre-compiled list of known/expected filenames (targets), and a list of candidates to evaluate and voilà! The output is a *similarity score*.

As you can imagine by now, this approach may be applied in many, many other cases. Here's a [tweet](https://twitter.com/ateixei/status/972100328899399685) I posted a while ago:

```
If you use #splunk and you get email logs/headers in.
Install TA-fuzzy and quickly find similar emails given a confirmed malicious one. 
```

## Data preparation
The lookup table `unique_processes.csv` referenced below contains a list of file names (absolute path) originating from eventlogs (event ID 4688), the very same can be achieved with `sysmon` or any other data source generating process names (AV, EDRs, etc).

## Fuzzy Search for Splunk (App)
Thanks to a guy called John Landers, below you can find the app that leverages a python library ([fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy)) that implements the concept:

[https://splunkbase.splunk.com/app/3109/](https://splunkbase.splunk.com/app/3109/)

### SPL query prototype
```
| inputlookup unique_processes.csv
| rex mode=sed field=New_Process_Name "s/.+\\\(\S+\.\S{3})$/\1/"
| eval New_Process_Name=lower(New_Process_Name)
| stats count by New_Process_Name

| fuzzy wordlist="svchost.exe,chrome.exe,explorer.exe,firefox.exe,lsass.exe,winlogon.exe,iexplore.exe,conhost.exe,rundll32.exe,wininit.exe" type=simple compare_field=New_Process_Name

| where (fuzzywuzzy__max_match_ratio>89) AND (fuzzywuzzy__max_match_ratio<100)

| rex field=fuzzywuzzy__max_match_word "^(?<target>\S+\.exe)/\S+$"
| dedup 5 target sortby -num(fuzzywuzzy__max_match_ratio)
| sort 0 target, -num(fuzzywuzzy__max_match_ratio)
| table target fuzzywuzzy__max_match_ratio New_Process_Name
```
The `dedup` command filters in only the *top 5* scores per target name that are higher than 89 and lower than 100 (exact match). Also, the query above uses a lookup as an input (candidates), but you can use the same logic in a rule, based on the output of a search given that the `fuzzy` command is executed for every row.

## Triage / Analysis
The higher the score (*fuzzywuzzy__max_match_ratio*), the more similar the candidate process name will be to the target one. Of course, in case of a suspicious process name, md5/sha hashes comparison is one of the ways to validate a case. So preparing a list of legitimate hashes (ex.: NSRL) is something to think upfront.

As expected, the bigger the list of targets or the shorter the process name, the more false-positives you encounter. You may need to tweak the threshold (`where` command line) if you are able to spend more time on data preparation and split candidates in different data sets.
