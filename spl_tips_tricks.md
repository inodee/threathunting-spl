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
Official doc: http://docs.splunk.com/Documentation/Splunk/7.0.0/SearchReference/Makeresults
