# Example Sysmon Events

This directory contains sample Sysmon logs and a python script to print them to standard out.  This will help to see what the raw Sysmon event slook like when writing additional parsing.  These events were collected from a Windows 10 host that had Powershell Empire installed.

Unzip PSE.json.gz

~~~
gunzip PSE.json.gz
~~~

Use sysmon-stdout.py to parse JSON and print to standard out.

~~~
python sysmon-stdout.py PSE.json 
~~~


