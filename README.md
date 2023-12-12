# WMI

WMI permenant event subscription to monitor new files dropped in a specific folder and check them using Yara for certain Web Shell patterns. it will log to a file you choose.
The script monitors a folder called c:\\\\monitorme and line 9 change it to your web server folders to monitor for newly drop ASP/ASPX files
rules.yar was built by  lnxg33k
* How to use the script
  * C:\\monitor\\yara\\yara64.exe is the path to Yara for windows excutable change it with the relevant folder you have
  * C:\\monitorme the folder to monotir
  * C:\\monitor\\yara\\rules.yar the Yara Rules to check for
  * C:\\test.txt log file location

