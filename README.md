# Aspx Webshell Detection Through WMI and Yara

WMI permenant event subscription to monitor new files dropped in a specific folder and check them using Yara for certain Web Shell patterns. it will log to a file you choose.
The script monitors a web folder for newly drop ASP/ASPX files and check if they have any signs of webshell code in them
rules.yar was built by  lnxg33k
* How to use the script
  * C:\\monitor\\yara\\yara64.exe is the path to Yara for windows excutable change it with the relevant folder to you
  * C:\\monitorme the folder to monotir
  * C:\\monitor\\yara\\rules.yar the Yara rule to check for
  * C:\\test.txt log file location

