# Detection surface for any security-aware data source
This does not turn you into a threat hunter or detection engineer but will definitely give you some leads for an initial detection surface analysis, especially for new data sources.

This should not be a recurrent query at all, but used for initial detection surface. Query time/performance varies per index density, # of sourcetypes and of course how many days you look back.

```
| tstats count where index=any TERM(exploit) by index, sourcetype, _time span=1d | eval matches="exploit"

| append [ | tstats count where index=any TERM(malware) by index, sourcetype, _time span=1d | eval matches="malware" ]
| append [ | tstats count where index=any TERM(virus) by index, sourcetype, _time span=1d | eval matches="virus" ]
| append [ | tstats count where index=any TERM(attack)  by index, sourcetype, _time span=1d | eval matches="attack" ]
| append [ | tstats count where index=any TERM(brute) by index, sourcetype, _time span=1d | eval matches="brute" ]
| append [ | tstats count where index=any TERM(alert) by index, sourcetype, _time span=1d | eval matches="alert" ]
| append [ | tstats count where index=any TERM(violation) by index, sourcetype, _time span=1d | eval matches="violation" ]
| append [ | tstats count where index=any TERM(critical) by index, sourcetype, _time span=1d | eval matches="critical" ]
| append [ | tstats count where index=any TERM(detected) by index, sourcetype, _time span=1d | eval matches="detected" ]
| append [ | tstats count where index=any TERM(botnet) by index, sourcetype, _time span=1d | eval matches="botnet" ]
| append [ | tstats count where index=any TERM(risk) by index, sourcetype, _time span=1d | eval matches="risk" ]

| stats sparkline, sum(count) AS event_count, values(matches) AS macthes by index, sourcetype
```
