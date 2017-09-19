rule CMD : webshell
{
	meta:
		author		= "Ahmed Shawky"
		date		= "17, Jul 2017"
		description	= "Catch ASP webshells"
	strings:
		$a = "cmd.exe" wide ascii nocase fullword
		$b = "xp_cmdshell" wide ascii nocase
		$c = /eval\s*\(/	wide ascii nocase
		$d = "system.diagnostics" wide ascii nocase fullword
		$e = "system.net.networkinformation" wide ascii nocase fullword
		$f = "Microsoft.Management" wide ascii fullword
	condition:
		any of them
}


rule SQL : webshell
{
	meta:
		author		= "Ahmed Shawky"
		date		= "19, Jul 2017"
		description	= "Catch ASP webshells"
	strings:
		$a = "system.data.sqlclient" wide ascii nocase fullword
	condition:
		any of them
}
