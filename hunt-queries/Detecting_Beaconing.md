index=proxy sourcetype=whatever url=*

| eval current_time=_time

| sort 0 + current_time

| streamstats global=f window=2 current=f last(current_time) AS previous_time by src url

| eval diff_time=current_time-previous_time

| eventstats count, stdev(diff_time) AS std by src url 

| where std<5 AND count>100

| stats count AS AS conn_count, dc(src) AS unique_sources, values(http_method) AS methods,
        values(http_user_agent) AS agents, values(std) AS diff_deviation, values(category) AS category
        BY url

| sort 0 - conn_count