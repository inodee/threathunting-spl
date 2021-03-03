Sourcetype agnostic query focused on webserver/waf/ng:fw logs for HAFNIUM based on IOCs provided here: https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/.

** Please fill in with your indexes and sourcetypes  **

Don't do this at home! (unles you have bloomfilter powers and good Splunk admins around you!)

** Please fill in with your indexes and sourcetypes  **

```
index IN (*) sourcetype IN (*) ((owa auth) OR (ecp (default OR main OR js)) OR (aspnet aspx))

| eval path_match=if(match(_raw, "(?i)(/owa/auth|/ecp/|/aspnet_client)"), "Path matches", null())
| eval agent_match=if(match(_raw, "(?i)(DuckDuckBot|facebookexternalhit|Baiduspider|Bingbot|Googlebot|Konqueror|Yahoo.*Slurp|YandexBot|Mozilla/5.0.\(X11;.Linux.x86_64\).AppleWebKit|antSword|ExchangeServicesClient|python-requests)"), "Agent matches", null())
| eval ip_match=if(match(_raw, "(?i)(103\.77\.192\.219|104\.140\.114\.110|104\.250\.191\.110|108\.61\.246\.56|149\.28\.14\.163|157\.230\.221\.198|167\.99\.168\.251|185\.250\.151\.72|192\.81\.208\.169|203\.160\.69\.66|211\.56\.98\.146|5\.254\.43\.18|80\.92\.205\.81)"), "IP matches", null())
| eval has_ext=if(match(_raw, "(?i)\.(js|aspx)"), "Has js/aspx extension", null())

| where (isnotnull(path_match) AND isnotnull(agent_match)) OR isnotnull(ip_match)

| stats sparkline, count, values(path_match) AS path_match, values(agent_match) AS agent_match, values(ip_match) AS ip_match, values(has_ext) AS has_ext, latest(_raw)
  BY index, sourcetype
```


