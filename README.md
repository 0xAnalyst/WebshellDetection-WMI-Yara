# WMI
WMI permenant event subscription to monitor new files dropped in a specific folder and  check them using Yara for certain Web Shell patterns. it will log to a file you choose. 
The script monitors a folder called c:\\\\monitorme and line 9 change it to your web server folders to monitor for newly drop ASP/ASPX files
rules.yar is the work of Ahmed Shawky lnxg33k

1-  C:\monitor\yara\yara64.exe is the path to Yara for windows excutable change it with the relevant folder you have
2-  C:\monitorme the folder to monotir 
3-  C:\monitor\yara\rules.yar the Yara Rules to check for 
4-  C:\test.txt log file location
