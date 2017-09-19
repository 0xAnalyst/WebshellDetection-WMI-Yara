$instanceFilter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
$instanceFilter.QueryLanguage = "WQL"
<# folder to monitor in the query below 
#>
$query = @"
 Select * from __InstanceCreationEvent within 5
 where targetInstance isa 'Cim_DirectoryContainsFile'
 and targetInstance.GroupComponent = 'Win32_Directory.Name="c:\\\\monitorme"' 
"@
#Event Filter
$instanceFilter.Query = $query
$instanceFilter.Name = "WebShellWatcherfilter"
$instanceFilter.EventNamespace = 'root\cimv2'
$result = $instanceFilter.Put()
$newFilter = $result.Path
#Event Consumer 
$instanceConsumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
$instanceConsumer.Name ='WebShellWatcherconsumer'
$instanceConsumer.ExecutablePath="C:\\Windows\\System32\\cmd.exe"
$instanceConsumer.CommandLineTemplate="/c C:\monitor\yara\yara64.exe -s  C:\monitor\yara\rules.yar C:\monitorme  -n > C:\test.txt" 
<# 
1-  C:\monitor\yara\yara64.exe is the path to Yara for windows excutable
2-  C:\monitorme folder to monitor
3-  C:\monitor\yara\rules.yar the Yara Rules to check for 
4-  C:\test.txt log file locaiton
#>
$result = $instanceConsumer.Put()
$newConsumer = $result.Path
#Bind filter and consumer
$instanceBinding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
$instanceBinding.Filter = $newFilter
$instanceBinding.Consumer = $newConsumer
$result = $instanceBinding.Put()
$newBinding = $result.Path
