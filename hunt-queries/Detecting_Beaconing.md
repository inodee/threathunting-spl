# How to detect beaconing traffic with Splunk?
I've seen people attempting to do that in many ways but mainly around [dataviz](https://pleasefeedthegeek.wordpress.com/2012/12/20/detecting-malware-beacons-using-splunk/), without using a more systematic approach. Besides the dashboard appeal, another reason for that lies in the fact users do not leverage or simply aren't aware about the power of `eventstats` and `streamstats` commands, sticking to `stats`command only.

Here the approach basically combines all those commands plus plain, simple standard deviation formula to detect variance in the time differences within multiple similar consecutive connections.

## The scenario
Assuming you are collecting proxy events (Squid, Bluecoat, IronPort, etc), one simple idea is to check the difference between similar connections established at different times. For that you may pick two entities from a connection, say *source host* and *URL*, and them calculate the delta (*_time*) between those connections.

For proxy events that are categorized (News, Search Engines, Sports, Adult, etc), you may even filter in/out what is more relevant or applicable to you or your environment. In case of firewall logs, the same applies but you may need to add extra entities to analize the flows (e.: source host, destination host and destination port).

### The recipe
Basically, assuming the last 24 hours as an example, the following instructions are being executed via SPL code:

1. Retrieve proxy events containing a non-null URL;
2. Sort them by time (epoch)
3. For every 2 consecutive events matching the same source host and URL,
    1. calculate the time difference between those events, in seconds
4. Once that difference is calculated for all events, append to every row/event (per source host and URL):
    1. the number of events matched (count)
    2. the standard deviation of the time differences between consecutive events
5. Filter in only those rows where the standard deviation is below 5 and with count greater than 100 (thresholds may be adusted)
6. Finally, group every relevant entity/field by URL, incluing the count of unique source hosts and start checking the list.

#### SPL query prototype
```
index=proxy sourcetype=whatever url=*

| eval current_time=_time

| sort 0 + current_time

| streamstats global=f window=2 current=f last(current_time) AS previous_time by src, url

| eval diff_time=current_time-previous_time

| eventstats count, stdev(diff_time) AS std by src, url 

| where std<5 AND count>100

| stats count AS AS conn_count, dc(src) AS unique_sources, values(http_method) AS methods,
        values(http_user_agent) AS agents, values(std) AS diff_deviation, values(category) AS category
        BY url
```
## Triage / Analysis
The closer the deviation is to zero, the higher the chances of the connection being related to a process being executed in a very regular interval, which is one of main characteristics of beaconing traffic.

As expected, most automated processes are detected via this method (AV updates, legitimate agents, etc) so if you proxy offers categorization it's easier to spot the context around the accessed URL. However, that does not mean Google or any other frequent accessed resources should be filtered out as bad guys are also leveraging that as a covert channel.

High number of connections with low values for deviation, combined with low number of sources (targets) is a good starting point. Later *bytes_out* or any other relevant field can be added to provide better context for analysis.
