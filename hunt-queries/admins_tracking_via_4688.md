# Admin account tracking via Eventlog ID 4688 (New Process)

In case you are auditing 4688 - which is not a simple task for big/enterprise environments, here's just another way to benefit from it.

Below (base) query will enable you to track users executing commands with admin privileges - assuming you are using the default Windows TA/App:

#### SPL query prototype
```
index=X sourcetype=Y EventCode=4688 Token_Elevation_Type="*(2)"
```

Change X/Y for your index/sourcetype values and make sure you leverage your SPL-foo to properly extract the username from Account_Name multi-value field.

Be sure to check all bottom notes from Microsoft Docs, they are really well done. Here's the entry for 4688 event:

https://docs.microsoft.com/en-us/windows/device-security/auditing/event-4688

And here's the hint to come up with this hunt:

> Monitor for Token Elevation Type with value TokenElevationTypeDefault (2) on standard workstations, when Subject\Security ID lists a real user account, for example when Account Name doesn’t contain the $ symbol. This means that a user ran a program using administrative privileges.
