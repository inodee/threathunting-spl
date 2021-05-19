# How to detect Authentication Brute Force attacks with Splunk?

![image](https://user-images.githubusercontent.com/14159692/117003810-9b6c8200-ace5-11eb-8627-cf944a0da807.png)

**TL;DR:** check the presentation slides and recording (suggested) and then refer to **Usage** section below.

This is a companion blog post to the [Splunk BSides 2021](https://usergroups.splunk.com/events/details/splunk-bsides-splunk-2021-community-presents-bsides-splunk-2021/) presenttion *"The ultimate Authentication Brute-Force detection using super stats"* delivered on May 4th. Slides and Recording are available below:

* [Slides](https://github.com/bsidessplunk/2021/blob/main/The%20ultimate%20Authentication%20Brute-Force%20detection%20using%20super%20stats/The%20ultimate%20Authentication%20Brute-Force%20detection%20using%20super%20stats.pdf)
* [Recording](https://www.youtube.com/watch?v=mVyRL1zSFDQ)

## Changelog
What has changed since the presentation/recording time, after getting feedback and applying some devel improvements?

1. Added a clear list of **successful** targets (accounts) to the _**reason**_ field, where the attack is described in details.
2. Introduced _**outer_tspan**_ field. This way, the faster Vanilla BF attack threshold (# of attempts) is calculated within a smaller, configurable timespan (_**tspan**_), while the other slower attacks (Mass BF, Password Spray and Targeted BF) have their thresholds calculated over a longer, also configurable timespan.
3. For Vanilla and Password Spray attacks, besides regular thresholds, a new constraint was added to the attack condition: _**successful_rate < 0.33**_. This filters out most cases where multiple accounts authenticate via the same gateway or jump host (Password Spray), and when the number of successful attempts is too high compared to total events, which does not consititute a BF atack scenario, assuming most attempts will actually fail.

## Usage
First thing to do is making sure the following attributes (fields) are properly extracted from your data source (events):
1. **_origin_**: that should be the value holding the (host) origin of the attack. Example: _src_, _src_ip_.
2. **_target_**: that should be the value holding the (account) target of the attack. Example: _user_, _user_id_.
3. **_action_**: that should be the value holding the authentication outcome. Example: _action_, _vendor_action_.

Needless to say, this detection is time sensitive, meaning `_time` value should be extracted properly otherwise output is not reliable.

Next, replace the first line of the detection template query to match your target data source, apply filters as necessary. For example:

`index=security sourcetype="vpn" action IN ("success", "failure")`

Then, rename or assign those mandatory values appropriately right after the base query:

For **_origin_**: `| eval origin=src` or `| eval origin=src_ip`.
For **_target_**: `| eval target=user` or `| eval origin=coalesce(user, user_id)`.

The _action_ (or _vendor_action_) value determines if an authentication is successful or not, that is another key aspect influencng in this detection quality, make sure you only count on relevant events. Here we simply need to collect the times when each outcome happens. For example:
```sql
| eval failure_time=if(match(action, "(?i)fail"), _time, null()) ``` matches *fail* case-insensitive ```
| eval success_time=if(match(action, "(?i)(success|pass)"), _time, null()) ``` flag a successful auth ```
```
In the end, the `origin` and `target` fields can be later reverted back to their original field names keeping the normalization/schema:
```sql
| rename origin AS src, target AS user
```

### Customization & Thresholds
The `outer_tspan` parameter defines the timespan in which non-Vanilla BF (slower) attacks are detected:
```sql
| bin _time span=10min AS outer_tspan ``` Default: 10min ``` 
```
The `tspan` parameter defines the timespan in which the Vanilla BF attack (faster) are detected. That's set in the following part:
```sql
| streamstats time_window=10s min(_time) AS tspan by origin, target, outer_tspan ``` Default: 10s ```
```
The `attack_th_global` value defines the max # of failed attempts before flagging a Vanilla BF attack:
```sql
| eval attack_th_global=5 
```
Note that this number is also used as part of the triggering condition for the Password Spray detection below.

The `attack_th` value is declared right before each code block for detecting non-Vanilla attacks and it comprises the max # of failed attempts before flagging an attack. The detection template below ships with the following default values:
- Mass Brute-Force Attack: 4
- Password Spray Attack: 5
- Targeted Brute-Force Attack: 5

Those should generate exactly 7 records as part of the results (detection output) when ran against the demo dataset. Set them accordingly.

Using dynamic thresholds is also encouraged but not covered in this material. Using lookups per sourcetype or client/tenant (MSSPs) is highly encouraged.

## Detection Query Template (SPL)
```php
index=auth action=*

| eval origin=src
| eval target=user
  
| eval failure_time=if(action="failure", _time, null())
| eval success_time=if(action="success", _time, null()) 
  
| bin _time span=10min AS outer_tspan

| sort 0 +num(_time)

| streamstats time_window=10s min(_time) AS tspan by origin, target, outer_tspan

| stats min(_time) AS start_time, max(_time) AS end_time, count(failure_time) AS count_fail, count(success_time) AS count_success
  BY origin, target, tspan, outer_tspan

| eval default_target=if(match(target, "^(?i)(administrator|admin|root|guest|test|backup|info|contact|ubnt|web|admin1|not available)(@\S+)*$"), 1, 0)   

| eval attack_th_global=5  
| eval attack_span=(1+end_time-start_time)
| eval attack_rate=ceil((count_fail+count_success)/attack_span)
| eval success_rate=count_success/(count_fail+count_success)

| eval signature=case(
  count_fail>attack_th_global AND count_success>0 AND success_rate<0.33, "Potential Successful Brute-Force Attack",
  count_fail>attack_th_global AND success_rate<0.33, "Potential Brute-Force Attack")

| eval reason=if(isnotnull(signature), signature.": There were [".count_fail."] failed attempts and [".count_success."] successful login(s) observed from origin [".origin."] towards [".target."] over ".attack_span." second(s) between ".strftime(start_time,"%F %T")." and ".strftime(end_time,"%F %T").". Rate: ~".attack_rate." attempts/s.", null())
 
| eval bf_target=if(isnotnull(signature), target, null())  
| eval attack_target=if(count_fail>0, target, null())     
| eval successful_target=if(count_success>0, target, null())

| eventstats min(start_time) AS start_time_by_origin, max(end_time) AS end_time_by_origin, sum(count_success) AS count_success_sum, sum(count_fail) AS count_fail_sum, avg(count_fail) AS count_fail_avg, dc(bf_target) AS count_bf_target, dc(attack_target) AS count_attack_target, values(target) AS target_values, values(successful_target) AS successful_target
  BY origin, outer_tspan

| eval attack_th=4
| eval attack_span=(1+end_time_by_origin-start_time_by_origin)
| eval attack_flag=if(count_bf_target>attack_th, 1, 0)

| eval signature=if(attack_flag=1, mvappend("Mass Brute-Force Attack", signature), signature)
| eval reason=if(attack_flag=1, mvappend("Mass Brute-Force Attack: more than ".attack_th." brute-force targets observed from same origin [".origin."].", reason), reason) 

| eval attack_th=5
| eval success_rate=count_success_sum/(count_fail_sum+count_success_sum)
| eval attack_flag=case(
  count_attack_target>attack_th AND count_fail_avg<=attack_th_global AND count_success_sum>0 AND success_rate<0.33, "Potential Successful",
  count_attack_target>attack_th AND count_fail_avg<=attack_th_global AND success_rate<0.33, "Potential",
  1=1, null())

| eval signature=if(isnotnull(attack_flag), mvappend(attack_flag." Password Spray Attack", signature), signature)

| eval reason=if(isnotnull(attack_flag), mvappend(attack_flag." Password Spray Attack: there were [".count_fail_sum."] failed attempts (~".ceil(count_fail_avg)."/attacked target) and [".count_success_sum."] successful login(s) observed from origin [".origin."] towards [".count_attack_target."] targets [".mvjoin(target_values, ", ")."] over ".attack_span." second(s) between ".strftime(start_time_by_origin,"%F %T")." and ".strftime(end_time_by_origin,"%F %T").". Successful target(s): ".coalesce(mvjoin(successful_target, ", "), "none").".", reason), reason)

| eval attack_origin=if(default_target=0 AND count_fail>0, origin, null())  

| eventstats min(start_time) AS start_time_by_target, max(end_time) AS end_time_by_target, sum(count_success) AS count_success_sum, sum(count_fail) AS count_fail_sum, dc(attack_origin) AS count_attack_origin, values(attack_origin) AS attack_origin_values, values(successful_target) AS successful_target
  BY target, outer_tspan

| eval attack_th=5
| eval attack_span=(1+end_time_by_target-start_time_by_target)
| eval attack_flag=case(
  count_attack_origin>attack_th AND count_fail_sum>=count_success_sum AND count_success_sum>0, "Potential Successful", 
  count_attack_origin>attack_th AND count_fail_sum>=count_success_sum, "Potential",
  1=1, null())

| eval signature=if(isnotnull(attack_flag), mvappend(attack_flag." Targeted Brute-Force Attack", signature), signature)

| eval reason=if(isnotnull(attack_flag), mvappend(attack_flag." Targeted Brute-Force Attack: there were [".count_fail_sum."] failed attempts and [".count_success_sum."] successful login(s) observed from multiple origins [".mvjoin(attack_origin_values, ", ")."] towards target [".target."] over ".attack_span." second(s) between ".strftime(start_time_by_target,"%F %T")." and ".strftime(end_time_by_target,"%F %T").". Successful target(s): ".coalesce(mvjoin(successful_target, ", "), "none").".", reason), reason)

| where isnotnull(signature) 

| stats min(start_time) AS start_time, max(end_time) AS end_time, values(target) AS target, values(signature) AS signature, values(reason) AS reason
  BY origin

| eval attack_hash=md5(mvjoin(mvappend(reason, ""), "")) 

| stats min(start_time) AS start_time, max(end_time) AS end_time, values(origin) AS origin, values(target) AS target, values(signature) AS signature, values(reason) AS reason
  BY attack_hash

| rename origin AS src, target AS user
| fields - attack_hash
```

## Sample dataset used during the presentation (SPL)
![image](https://user-images.githubusercontent.com/14159692/117002841-5eec5680-ace4-11eb-87be-6b68ee9a395b.png)
- Remove comments if Splunk version < 8.1)
- Adjust the last line (`collect`) to your test/demo index
```php
| makeresults ``` all events within 1h (demo rule detection interval) ``` 
| where 0=1 ``` filters out empty record ```

| append [ | makeresults count=3 | eval _time=relative_time(now(), "-0s"), src="pokey", signature="User failed to authenticate", action="failure", user="admin" ] ``` vanilla attack```
| append [ | makeresults count=3 | eval _time=relative_time(now(), "-1s"), src="pokey", signature="User failed to authenticate", action="failure", user="admin" ]
| append [ | makeresults count=6 | eval _time=relative_time(now(), "-100s"), src="blinky", signature="User failed to authenticate", action="failure", user="backup" ] ``` successful attack```
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-99s"), src="blinky", signature="User login successful", action="success", user="backup" ]

``` noisy attack```
| append [ | makeresults count=8 | eval _time=relative_time(now(), "-10min"), src="speedy", signature="User failed to authenticate", action="failure", user=mvappend("admin", "root", "test", "administrator", "guest", "info", "contact") | mvexpand user ]
``` fast targeted attack```
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-30min"), user="princesspeach", signature="User failed to authenticate", action="failure", src=mvappend("bird", "jordan", "johnson", "pippen", "robinson", "clyde", "malone") | mvexpand src ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-50min"), user="larrykoopa", signature="User failed to authenticate", action="failure", src=mvappend("bird", "jordan", "johnson", "pippen", "robinson", "clyde") | mvexpand src ]
``` slow targeted attack```
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-10min"), user="donkeykongjr", signature="User login successful", action="success", src="bird" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-15min"), user="donkeykongjr", signature="User failed to authenticate", action="failure", src="jordan" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-20min"), user="donkeykongjr", signature="User failed to authenticate", action="failure", src="johnson" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-25min"), user="donkeykongjr", signature="User failed to authenticate", action="failure", src="pippen" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-30min"), user="donkeykongjr", signature="User failed to authenticate", action="failure", src="robinson" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-35min"), user="donkeykongjr", signature="User failed to authenticate", action="failure", src="clyde" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-40min"), user="donkeykongjr", signature="User failed to authenticate", action="failure", src="malone" ]

``` fast password spray ```
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-55min"), src="shadow", signature="User failed to authenticate", action="failure", user=mvappend("admin", "root", "test", "administrator", "guest", "info", "contact") | mvexpand user ]
``` slow password attack```
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-10min"), src="pinky", signature="User login successful", action="success", user="admin" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-15min"), src="pinky", signature="User failed to authenticate", action="failure", user="root" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-20min"), src="pinky", signature="User failed to authenticate", action="failure", user="test" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-25min"), src="pinky", signature="User failed to authenticate", action="failure", user="administrator" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-30min"), src="pinky", signature="User failed to authenticate", action="failure", user="guest" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-35min"), src="pinky", signature="User failed to authenticate", action="failure", user="info" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-40min"), src="pinky", signature="User failed to authenticate", action="failure", user="contact" ]

``` random noise/legit sessions ```
| append [ | makeresults count=4 | eval _time=relative_time(now(), "-6s"), src="workstation10", signature="User failed to authenticate", action="failure", user="administrator" ]  ``` 4 failed, then success (FP) ```
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-0s"), src="workstation10", signature="User login successful", action="success", user="administrator" ]
| append [ | makeresults count=3 | eval _time=relative_time(now(), "-1s"), src="speedy", signature="User failed to authenticate", action="failure", user="backup" ]  ``` speedy below threshold (FP) ``` 
| append [ | makeresults count=3 | eval _time=relative_time(now(), "-10s"), src="laptop1", signature="User failed to authenticate", action="failure", user="root" ] ``` legit/noise (FP) ```
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-0s"), src="laptop1", signature="User login successful", action="success", user="root" ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-0s"), src="laptop2", signature="User login successful", action="success", user="admin" ]

``` stealth attack ```
| append [ | makeresults count=3 | eval _time=relative_time(now(), "-20s"), src="dcarasso", signature="User failed to authenticate", action="failure", user="buttercup" | bin _time span=10s | streamstats count | eval _time=_time+(10-count) ]
| append [ | makeresults count=3 | eval _time=relative_time(now(), "-20s"), src="dcarasso", signature="User failed to authenticate", action="failure", user="buttercup" | bin _time span=10s | streamstats count | eval _time=_time+(9+count)  ]
| append [ | makeresults count=1 | eval _time=relative_time(now(), "-10s"), src="dcarasso", signature="User login successful", action="success", user="buttercup" | bin _time span=10s | eval _time=_time+3 ]
| fields - count
| collect index=auth

```
