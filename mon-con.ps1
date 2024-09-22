##############################################################################
# MON-CON - MONitor CONnectivity
#           ..is a PowerShell script to monitor your network connection
##############################################################################
# Note: this script only works w/ Powershell7 (as it relies on thread jobs)
#Requires -Version 7

<#
	.SYNOPSIS
	MON(itor)-CON(nection), test and monitor your internet connection.

	.DESCRIPTION
	This script does monitor a chain of interfaces / connections.

	DEV<->LAN<->ROUTER<->INTERNET<->Ext.SERVER

	IPv4 and IPv6 are tested concurrently if available.

	From your local system, all the way up the the mighty internet, it tests
	different intermediate hops. These hops are automatically determined.

	It runs in the foreground and cyclically generates information on the console.

	There is a number of Ping and DNS tests already defined and enabled.
	These tests should allow debugging an internet connection and help identify
	the cause for spurious connectivity problems.

	Each test can either pass (green) or fail (red).  
	Warnings (yellow) if a ping tests RTT is high or if a DNS TTL is 0.

	.PARAMETER BeepOnError
	Switch that enables acoustic feedback (beeping) for every test that failed.

	.PARAMETER Display
	Define [enum] how to scroll the output and which information to retain.  
	Full    -> Retain all test lines, scroll after each test (Default)  
	Warning -> Retain lines with Error or Warning  
	Error   -> Retain only lines with Error  
	Note: Output will also retain margin, i.e. one line before/after an event.

	.PARAMETER TestInterval
	Defines the [int] cycle time (in milliseconds) at which tests are repeated.  
	Default is 3000(ms), i.e. 3 seconds.  
	NOTE: in most setups, 3 (seconds) is the lowest usable value.

	.PARAMETER Timeout
	The [int] time to wait for any individual test to complete, in milliseconds.
	Default is 2000(ms), i.e. 2 seconds.  
	NOTE: in most setups, 2 (seconds) is the lowest viable value.

	.PARAMETER FocusTest
	With this [string] parameter only the Test requested is executed.
	Also, all of the tests output is being piped and made visible to the user.

	.PARAMETER Iterations
	Define the [int] number of cycles that the test will run.

	.INPUTS
	None. You can't pipe objects.

	.OUTPUTS
	Only Text (as this is a command-lineline live monitoring tool).

	.EXAMPLE
	PS> .\mon-con.ps1 -BeepOnError -Display Warning -Timeout 2500 -Verbose

	.NOTES
	Author  : Kai Poggensee  
	Version : 0.12 (2024-09-19) - Documentation cleanup
#>

##############################################################################
# TODO: move test statistics to class instead of using ugly _PASS _FAIL hack.
##############################################################################

#
# command-line parameter definitions
#

[CmdletBinding()]

param(
	[Parameter()]
	[switch]$BeepOnError,
	[Parameter()]
	[ValidateSet('Full','Warning','Error')]
	[string]$Display = 'Full',
	[Parameter()]
	[int]$TestInterval = 3000,
	[Parameter()]
	[int]$Timeout = 2000,
	[Parameter()]
	[string]$FocusTest,
	[Parameter()]
	[int]$Iterations = -1
)

#
# default configuration options (override via config file)
#

# The DNS to use when doing DNS tests against a public DNS
$PUBLIC_DNS_SERVER_NAME = "one.one.one.one"

# The Domain name (prefixed with a dynamic counter) to use for testing DNS
$DNS_TEST_DOMAIN = "lowttl.poggensee.it" # TTL 30(s) for DNS testing

# Define the public host to use for external testing.
# NOTE: feasible choice is a host reachable always and everywhere, with HA
# Choose two hosts with one IP ODD the other EVEN, to test routing based LB
$EXT_TEST_HOST1 = "one.one.one.one"
$EXT_TEST_HOST2 = "security.cloudflare-dns.com"

# URLs where the script can query the hosts public IP
$PUBLIC_IPv4_URL = "https://www4.poggensee.it/ip"
$PUBLIC_IPv6_URL = "https://www6.poggensee.it/ip"


#
# read config file ('.mon-con.conf') - define config overrides there
#

if (Test-Path(".\.mon-con.conf")) {
	Get-Content .\.mon-con.conf | Invoke-Expression -ErrorAction SilentlyContinue
}


#
# global classes to use for objects
#

class IPConfigClass
{
	[ipaddress]$OwnLanIPv4
	[ipaddress]$OwnLanIPv6
	[ipaddress]$DefaultRouterIPv4
	[ipaddress]$DefaultRouterIPv6
	[string]$PublicDnsServerName
	[string]$LanDnsServerName
	[ipaddress]$PublicDnsServerIPv4
	[ipaddress]$PublicDnsServerIPv6
	[ipaddress]$LanDnsServerIPv4
	[ipaddress]$LanDnsServerIPv6
	[ipaddress]$AUXAddrIPv4
	[ipaddress]$AUXAddrIPv6
	[ipaddress]$PublicTestHost1AddrIPv4
	[ipaddress]$PublicTestHost1AddrIPv6
	[ipaddress]$PublicTestHost2AddrIPv4
	[ipaddress]$PublicTestHost2AddrIPv6
	
	[string] printDetails () # class method returning all
	{
		$retVal = ""
		foreach ($o in $this) {$retVal += $o}
		return $retVal
	}
}

class TestClass
{
	[string]$name
	[string]$descr
	[scriptblock]$code
	$args
	[string]$dynargvar
	[bool]$enabled
	[int]$testpass
	[int]$testfail
	[int]$testtimeout
	[int]$testunknown
}

class TestCollectionClass
{
	[TestClass[]]$tests
	
	[string] addressByName () # class method returning test with name
	{
		$retVal = $null
		foreach ($test in .this.$tests) { if ($_.name -eq "x") {} }
		return $retVal
	}
}


#
# constants
#

New-Variable -Option Constant -Name TIMEOUT_S -Value $($Timeout / 1000)
New-Variable -Option Constant -Name SLEEP_WAIT_QUANTUM -Value 100
New-Variable -Option Constant -Name IPv4_REGEXP -Value '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'


#
# functions
#

function getLocalHostIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		# NOTE: methodology of determining the address differs for IPv4 and v6
		#       for IPv6, use the fact that a public IPv6 assigned
		#       for IPv4 one needs to use pull it from the interface settings
		$IPConfig.OwnLanIPv4 = (hostname | Resolve-DnsName -QuickTimeout -type A -DnsOnly | Where-Object -Property section -eq "Answer" | select-object -first 1 | select -ExpandProperty IPAddress)
		$IPConfig.OwnLanIPv6 = (Invoke-WebRequest $PUBLIC_IPv6_URL -ConnectionTimeoutSeconds 2 -OperationTimeoutSeconds 2).Content
	} catch {
		Write-Warning "Own local IPs could not be determined. Falling back to localhost addresses."
		$IPConfig.OwnLanIPv4 = "127.0.0.1"
		$IPConfig.OwnLanIPv6 = "::1"
	} finally {
		Write-Host "Local (Own) IPv4 address:" $IPConfig.OwnLanIPv4
		Write-Host "Local (Own) IPv6 address:" $IPConfig.OwnLanIPv6
	}
}

function getDefaultRouterIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	$gateways = (Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.IPEnabled}).DefaultIPGateway
	foreach ($ip in $gateways) {
		if ($ip -match $IPv4_REGEXP)
		{
			$IPConfig.DefaultRouterIPv4 = $ip	
		} else {
			$IPConfig.DefaultRouterIPv6 = $ip
		}
	}
	Write-Host "Default IPv4 router:" $IPConfig.DefaultRouterIPv4
	Write-Host "Default IPv6 router:" $IPConfig.DefaultRouterIPv6

}

function getLanDnsServerName {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$LocalDnsAutoDetected = echo "exit" | nslookup.exe | Select-String -Pattern "^.*erver:.*" -CaseSensitive -Raw | Select-String -Pattern "[.:a-z0-9]*$" | % { $_.Matches } | % { $_.Value }		
		$IPConfig.LanDnsServerName = $LocalDNSAutoDetected
	} catch {
		Write-Error "Local DNS server could not be determined."
		exit
	} finally {
		Write-Host "Local DNS server name:" $IPConfig.LanDnsServerName
	}
}

function getPublicDnsServerIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$IPConfig.PublicDnsServerIPv4 = Resolve-DnsName -QuickTimeout -type A $PUBLIC_DNS_SERVER_NAME |  Where-Object -Property section -eq "Answer" | Select-Object -first 1 | select -ExpandProperty IPAddress
		$IPConfig.PublicDnsServerIPv6 = Resolve-DnsName -QuickTimeout -type AAAA $PUBLIC_DNS_SERVER_NAME | Where-Object -Property section -eq "Answer" | Select-Object -first 1 | select -ExpandProperty IPAddress
	} catch {
		Write-Warning "Public DNS server not resolved. Falling back to DNS server name."
		$IPConfig.PublicDnsServerIPv4 = $PUBLIC_DNS_SERVER_NAME
		$IPConfig.PublicDnsServerIPv6 = $PUBLIC_DNS_SERVER_NAME
	} finally {
		Write-Host "Public DNS IPv4 address:" $IPConfig.PublicDnsServerIPv4
		Write-Host "Public DNS IPv6 address:" $IPConfig.PublicDnsServerIPv6
	}
}


function getLanDnsServerIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$IPConfig.LanDnsServerIPv4 = Resolve-DnsName -QuickTimeout -type A $IPConfig.LanDnsServerName |  Where-Object -Property section -eq "Answer" | Select-Object -first 1 | select -ExpandProperty IPAddress
		$IPConfig.LanDnsServerIPv6 = Resolve-DnsName -QuickTimeout -type AAAA $IPConfig.LanDnsServerName | Where-Object -Property section -eq "Answer" | Select-Object -first 1 | select -ExpandProperty IPAddress
	} catch {
		Write-Warning "LAN DNS server not resolved. Falling back to DNS server name."
		$IPConfig.LanDnsServerIPv4 = $IPConfig.LanDnsServerName
		$IPConfig.LanDnsServerIPv6 = $IPConfig.LanDnsServerName
	} finally {
		Write-Host "LAN DNS IPv4 address:" $IPConfig.LanDnsServerIPv4
		Write-Host "LAN DNS IPv6 address:" $IPConfig.LanDnsServerIPv6
	}
}

function getAUXTestIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$IPConfig.AUXAddrIPv4 = Resolve-DnsName -QuickTimeout -type A -DNSOnly -NoHostsFile "$AUX_DNS_NAME." | Where-Object -Property section -eq "Answer" | Select-Object -last 1 | select -ExpandProperty IPAddress
		$IPConfig.AUXAddrIPv6 = Resolve-DnsName -QuickTimeout -type AAAA -DNSOnly -NoHostsFile "$AUX_DNS_NAME." | Where-Object -Property section -eq "Answer" | Select-Object -last 1 | select -ExpandProperty IPAddress
	} catch {
		Write-Warning "Could not get IPs of AUX, omitting"
		$IPConfig.AUXAddrIPv4 = "n/a"
		$IPConfig.AUXAddrIPv6 = "n/a"
	} finally {
		Write-Host "Router AUX Side IPv4 address:" $IPConfig.AUXAddrIPv4
		Write-Host "Router AUX Side IPv6 address:" $IPConfig.AUXAddrIPv6
	}
}

function getPublicTestIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$IPConfig.PublicTestHost1AddrIPv4 = Resolve-DnsName -QuickTimeout -type A -DNSOnly -NoHostsFile "$EXT_TEST_HOST1." | Where-Object -Property section -eq "Answer" | Select-Object -last 1 | select -ExpandProperty IPAddress
		$IPConfig.PublicTestHost1AddrIPv6 = Resolve-DnsName -QuickTimeout -type AAAA -DNSOnly -NoHostsFile "$EXT_TEST_HOST1." | Where-Object -Property section -eq "Answer" | Select-Object -last 1 | select -ExpandProperty IPAddress
		$IPConfig.PublicTestHost2AddrIPv4 = Resolve-DnsName -QuickTimeout -type A -DNSOnly -NoHostsFile "$EXT_TEST_HOST2." | Where-Object -Property section -eq "Answer" | Select-Object -last 1 | select -ExpandProperty IPAddress
		$IPConfig.PublicTestHost2AddrIPv6 = Resolve-DnsName -QuickTimeout -type AAAA -DNSOnly -NoHostsFile "$EXT_TEST_HOST2." | Where-Object -Property section -eq "Answer" | Select-Object -last 1 | select -ExpandProperty IPAddress
	} catch {
		Write-Warning "Could not resolve IPs of public test hosts, falling back to names."
		$IPConfig.PublicTestHost1AddrIPv4 = $EXT_TEST_HOST1
		$IPConfig.PublicTestHost1AddrIPv6 = $EXT_TEST_HOST1
		$IPConfig.PublicTestHost2AddrIPv4 = $EXT_TEST_HOST2
		$IPConfig.PublicTestHost2AddrIPv6 = $EXT_TEST_HOST2
	} finally {
		Write-Host "Public Server #1 IPv4 address:" $IPConfig.PublicTestHost1AddrIPv4
		Write-Host "Public Server #1 IPv6 address:" $IPConfig.PublicTestHost1AddrIPv6
		Write-Host "Public Server #2 IPv4 address:" $IPConfig.PublicTestHost2AddrIPv4
		Write-Host "Public Server #2 IPv6 address:" $IPConfig.PublicTestHost2AddrIPv6
	}
}

function getNetworkConfig {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	
	# determine local IP addresses
	getLocalHostIPs $IPConfig
	
	# determine LAN default routers
	getDefaultRouterIPs $IPConfig
	
	# determine DNS
	getPublicDnsServerIPs $IPConfig
	getLanDnsServerName $IPConfig
	getLanDnsServerIPs $IPConfig

	if (![string]::IsNullOrEmpty($AUX_DNS_NAME)) {
		# determine own AUX addresses
		getAUXTestIPs $IPConfig
	}

	# determine own Public test-host addresses
	getPublicTestIPs $IPConfig
}   

function throwOnCtrlC {
	while ([Console]::KeyAvailable) {
		$readKey = [Console]::ReadKey($True)
		if ($readKey.Modifiers -eq "Control" -and $readKey.Key -eq "C"){				
			# throw exception to be handled
			throw
		}
	}
	return $True
}

function clearCurrentConsoleLine {
	$CurrentLine  = $Host.UI.RawUI.CursorPosition.Y
	$ConsoleWidth = $Host.UI.RawUI.BufferSize.Width	
	[Console]::SetCursorPosition(0,($CurrentLine))
	[Console]::Write("{0,-$ConsoleWidth}" -f " ")
	[Console]::SetCursorPosition(0,($CurrentLine))
}

function writeSpin ($counter) {
	$spin = @('|', '/', '-', '\')
	$counter = $counter % $spin.Length
   
	Write-Host $spin[$counter] -NoNewLine

	$counter++
	$counter = $counter % $spin.Length
	
	return $counter
}

function jobsEvalThenPurge {

	foreach ($job in Get-Job) {

		$OutputJob = 0
		Write-Host " " -NoNewLine
		if ($job.State -eq 'Completed') {
			$vname = $job.Name + "_PASS"
			
			$jobOutput = Receive-Job -job $job -Keep
			if (!($jobOutput -match "Warning:")) {
				# TEST OK => GREEN
				Write-Host $job.Name -NoNewLine -ForeGroundColor Green
			} else {
				$warning = $warning + 1
				# WARNING => AMBER
				Write-Host $job.Name -NoNewLine -ForeGroundColor Yellow
				if ($VerbosePreference -or $DebugPreference) {
					$OutputJob = 1
				}
			}
		} elseif ($job.State -eq 'Failed') { # Fails means exception
			# FAILURE => RED
			if ($VerbosePreference -or $DebugPreference) {
				$OutputJob = 1
			}
			$vname = $job.Name + "_FAIL"
			$fail = $fail + 1
			Write-Host $job.Name -NoNewLine -ForeGroundColor Red
			if ($BeepOnError) {[Console]::Beep()}
		} elseif ($job.State -eq 'Stopped') {
			# job was stopped (the way to timeout)
			if ($VerbosePreference -or $DebugPreference) {
				$OutputJob = 1
			}
			$vname = $job.Name + "_FAIL" # TODO: separate timeout management
			$fail = 1
			Write-Host $job.Name -NoNewLine -ForeGroundColor Blue
		} else {
			# irregular (other state - e.g. unfinished)
			$vname = ""
			Write-Host $job.Name -NoNewLine -ForeGroundColor DarkGray
			continue
		}

		$temp = get-variable -name "$vname" -ValueOnly -ErrorAction SilentlyContinue
		$temp++
		set-variable -name "$vname" -value $temp -scope Script
		
		if (($VerbosePreference -and $OutputJob) -or $DebugPreference) {
			$jobOutput = Receive-Job -job $job

			if ($jobOutput -eq "") {
				$jobOutput = $job.Name + ": No output generated."
			}

			# output details of failure if verbose or always if debug
			if ($VerbosePreference -and $OutputJob) {
				Write-Host ""
				$jobOutput | Write-Verbose
			}
			elseif ($DebugPreference) {
				Write-Host ""
				$jobOutput | Write-Debug
			}
		}

		Remove-Job -job $job
	}
	return @{fails=$fail; warnings=$warning}
}


# 
# Generic test code definitions (used in the jobs the script spawns)
#

$SelftestDummyJobTestCode = {
	param (
		[Parameter(Position=0,mandatory=$True)]
		[string]$DEBUG_TESTOUTPUT
	)
	Write-Output "Starting Self-test job, total runtime 250ms."
	Write-Output "Sleeping 200ms..."
	Start-Sleep -Milliseconds 200
	Write-Output "Sleeping 50ms..."
	Start-Sleep -Milliseconds 50
	Write-Output "Parameter handed over for testing was: '$DEBUG_TESTOUTPUT'."
	Write-Output "Completing test with regular success status."
	return
}	


$DNSTestCode = {
	param (
		[Parameter(Position=0,mandatory=$True)]
		[string]$DNS_RECORD_TYPE,
		[Parameter(Position=1,mandatory=$True)]
		[string]$DNS_SERVER,
		[Parameter(Position=2,mandatory=$True)]
		[string]$TARGET,
		[Parameter(Position=3,mandatory=$False)]
		[bool]$OPT_NOREC = $False
	)
	# NOTE: appending a "." to the TARGET to make FQDN handed over and resolved
	$TargetFQDN = "$TARGET."
	if ($OPT_NOREC) {
		$output = Resolve-DnsName -type $DNS_RECORD_TYPE -server $DNS_SERVER -DNSOnly -NoHostsFile -NoRecursion -QuickTimeout -Name $TargetFQDN	2> $error
	} else {
		$output = Resolve-DnsName -type $DNS_RECORD_TYPE -server $DNS_SERVER -DNSOnly -NoHostsFile -QuickTimeout -Name $TargetFQDN 2> $error
	}

	if ($?) {
		$result = $output | Where-Object -Property name -eq "$TARGET" | Where-Object -Property type -eq "$DNS_RECORD_TYPE" | Where-Object -Property section -eq "Answer"
		if ($result) {
			$success = $True
			if ($result.TTL -eq 0) {
				Write-Output "Warning: Abnormal DNS entry TTL (0) returned."
				$warn = $True
			}
		} else {
			$success = $False
			Write-Output "Failure: Resolution did not yield '$DNS_RECORD_TYPE' entry for '$TargetFQDN'."
		}
	} else {
		$success = $False
		Write-Output "Failure: Resolve-DnsName returned with error, details from command (if any) below."
		Write-Output "$error"
	}
		
	# TODO: clean up reporting - below code should be considered a hack	
	$output | Out-String | Write-Output
	
	if ($success) { return } else { throw "Failed DNS test" }
}

$PingTestCode = {
	param (
		[Parameter(Position=0,mandatory=$True)]
		[int]$IPVER,
		[Parameter(Position=1,mandatory=$True)]
		[string]$TARGET,
		[Parameter(Position=2,mandatory=$False)]
		[int]$OPT_MAXHOPS = 128,
		[Parameter(Position=3,mandatory=$False)]
		[int]$TIMEOUT_PING
	)
	if ($TARGET.length -lt 1) {
		Write-Output "Missing or empty parameter TARGET. Aborting ping test."
		throw "Missing parameter TARGET"
	}
	
	if ($IPVER -eq 4) {
		$output = (ping -4 -n 1 -i $OPT_MAXHOPS -w $TIMEOUT_PING $TARGET) 2> $error
	} elseif ($IPVER -eq 6) {
		$output = (ping -6 -n 1 -i $OPT_MAXHOPS -w $TIMEOUT_PING $TARGET) 2> $error
	} else {
		Write-Output "Invalid parameter IPVER. Aborting ping test."
		throw "Invalid parameter IPVER set to '$IPVER'"
	}
	
	if ($?) {
		if ("$output" -match '\(0\%') { # match the 0 packets at 0% loss in a language agnostic way
			$success = $True

			(($output | Select-String -Pattern "=.*ms$" -Raw) -match "=\s?([0-9]*)ms$") > $null
			$RTT=[int]$matches[1]
			# Assumption: RTT can always be 100ms, but even long distance normally not exceeds 500ms
			if ($RTT -ge $(100 + ($OPT_MAXHOPS * 2))) {
				Write-Output "Warning: Ping RTT (round trip time) abnormally high: ${RTT}ms."
				$warn = $True
			}
		} else {
			Write-Output "Failure: Ping request sent but response missing (or after timeout of ${TIMEOUT_PING}s)."
			$success = $False
		}
	} else {
		Write-Output "Failure: Ping returned with an error, details from command (if any) below."
		Write-Output "$error"
		$success = $False
	}
	
	# TODO: clean up reporting - below code should be considered a hack	
	$output | Out-String | Write-Output
	
	if ($success) { return } else { throw "Failed ping test" }
}


#
# main() - initialize and start the tests
#

# disable Ctrl-c (to set up proper exit management)
[Console]::TreatControlCAsInput = $True

# increase process priority to "High", to have higher reliability in tests
$startupPriority = (Get-Process -Id $PID).PriorityClass
(Get-Process -Id $PID).PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High

# set up variables
$Cycle = 0
$CyclesWithFail = 0
$DNSTestDynPrefix = 0

$IPConfig = New-Object -TypeName IPConfigClass

# auto-detect settings
getNetworkConfig $IPConfig

#
# Define the tests
#
[TestClass[]]$tests = @(
	[TestClass]@{
		name='D4-PUB';
		descr='DNS resolve external hosts "A" record via generic public DNS server, using IPv4';
		code=$DNSTestCode;
		args=('A', $IPConfig.PublicDnsServerIPv4.IPAddressToString);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True
	}
	[TestClass]@{
		name='D6-PUB';
		descr='DNS resolve ext. hosts "AAAA" record via generic public DNS server, using IPv6';
		code=$DNSTestCode;
		args=('AAAA', $IPConfig.PublicDnsServerIPv6.IPAddressToString);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True;
	}
	[TestClass]@{
		name='D4-EXT';
		descr='DNS resolve an external "A" record via the local (LAN) DNS server, using IPv4';
		code=$DNSTestCode;
		args=('A', $IPConfig.LanDnsServerIPv4.IPAddressToString);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True
	}
	[TestClass]@{
		name='D6-EXT';
		descr='DNS resolve an ext. "AAAA" record via the local (LAN) DNS server, using IPv6';
		code=$DNSTestCode;
		args=('AAAA', $IPConfig.LanDnsServerIPv6.IPAddressToString);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True;
	}
	[TestClass]@{
		name='D4-INT';
		descr='DNS resolve an on-site hosts "A" record (no recursion), via IPv4';
		code=$DNSTestCode;
		args=('A', $IPConfig.LanDnsServerIPv4.IPAddressToString, $IPConfig.LanDnsServerName, [bool]1);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='D6-INT';
		descr='DNS resolve on-site hosts "AAAA" record (no recursion), via IPv6';
		code=$DNSTestCode;
		args=('AAAA', $IPConfig.LanDnsServerIPv6.IPAddressToString, $IPConfig.LanDnsServerName, [bool]1);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='P4-PB1';
		descr='Ping an external (public) system on its IPv4 address';
		code=$PingTestCode;
		args=('4', $IPConfig.PublicTestHost1AddrIPv4, 128, $Timeout);
		enabled=$True;
	}
	[TestClass]@{
		name='P6-PB1';
		descr='Ping an external (public) system on its IPv6 address';
		code=$PingTestCode;
		args=('6', $IPConfig.PublicTestHost1AddrIPv6, 128, $Timeout);
		enabled=$True;
	}
	[TestClass]@{
		name='P4-PB2';
		descr='Ping an external (public) system on its IPv4 address';
		code=$PingTestCode;
		args=('4', $IPConfig.PublicTestHost2AddrIPv4, 128, $Timeout);
		enabled=$True;
	}
	[TestClass]@{
		name='P6-PB2';
		descr='Ping an external (public) system on its IPv6 address';
		code=$PingTestCode;
		args=('6', $IPConfig.PublicTestHost2AddrIPv6, 128, $Timeout);
		enabled=$True;
	}
	[TestClass]@{
		name='P4-AUX';
		descr='Ping the Aux / user defined IPv4 adress';
		code=$PingTestCode;
		args=('4', $IPConfig.AUXAddrIPv4, 2, $Timeout);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='P6-AUX';
		descr='Ping the Aux / user defined IPv6 adress';
		code=$PingTestCode;
		args=('6', $IPConfig.AUXAddrIPv6, 2, $Timeout);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='P4-LAN';
		descr='Ping a host on the LAN via IPv4';
		code=$PingTestCode;
		args=('4', $IPConfig.DefaultRouterIPv4, 1, $Timeout);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='P6-LAN';
		descr='Ping a host on the LAN via IPv6';
		code=$PingTestCode;
		# NOTE: MUST NOT USE link local address due to Windows issue
		args=('6', $IPConfig.LanDnsServerIPv6, 1, $Timeout);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='P4-LOC';
		descr='Ping the localhost (assinged IP) via IPv4';
		code=$PingTestCode;
		args=('4', $IPConfig.OwnLanIPv4, 1, $Timeout);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='P6-LOC';
		descr='Ping localhost (assigned IP) via IPv6';
		code=$PingTestCode;
		args=('6', $IPConfig.OwnLanIPv6, 1, $Timeout);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='ST';
		descr='SelfTest the Powershell Jobs system';
		code=$SelftestDummyJobTestCode;
		args=("FooBar");
		dynargvar='';
		enabled=$True	
	}
)

# focus test mode, disabling all other tests
if ($FocusTest) {
	foreach ($test in $tests) {
		if ($test.name -eq $FocusTest) {
			$test.enabled = $True
		} else {
			$test.enabled = $False
		}
	}
}

$enabled_tests=0

# Output list of active tests and purpose in verbose mode
Write-Verbose "The following tests are enabled:"
foreach ($test in $tests) {
	if ($test.enabled) {
		Write-Verbose "- Test '$($test.name)': $($test.descr)"
		$enabled_tests++
	}
}

Write-Host ("Running tests with TestInterval (i.e. one cycle every) " + $TestInterval + " milliseconds")
Write-Host ("The timeout (of individual tests) is set to " + $Timeout + " milliseconds")


if ($TestInterval -le $Timeout) {
	Write-Host "NOTE: TestInterval less than or equal to Timeout, expect some hick-ups!"
}

$cycleStartTime = $programStartTime = Get-Date
$cycleStartTime = $cycleStartTime.AddMilliseconds(-$TestInterval)
$cycleStartTime = $cycleStartTime.AddMilliseconds(2*$SLEEP_WAIT_QUANTUM)


# main loop
try {
while (($Iterations -le 0) -or ($Cycle -lt $Iterations))
	{
	$stuffChars = ($Cycle.ToString().Length -lt 5) ? 5-$Cycle.ToString().Length : 0

	# NOTE: dedicated DNS names, entries crafted to have a very low TTL 
	#	   as to not measure cached -> but ensure external requests
	$SHORT_TTL_DNSTEST_HOST = "${DNSTestDynPrefix}.${DNS_TEST_DOMAIN}"

	# signal that we start
	if ($CyclesWithFail -gt 1) {
		Write-Host ((' ' * $stuffChars) + "#${Cycle}") -NoNewLine -ForeGroundColor Red
	} elseif ($CyclesWithFail -gt 0) {
		Write-Host ((' ' * $stuffChars) + "#${Cycle}") -NoNewLine -ForeGroundColor Yellow
	} else {
		Write-Host ((' ' * $stuffChars) + "#${Cycle}") -NoNewLine -ForeGroundColor Green
	}

	# rate limit tests, delay next start if needed
	$count = 0
	do {
		$currentTime = Get-Date
		$timeLapsedSinceLastCycle = ($currentTime - $cycleStartTime).Totalmilliseconds
		if (($timeLapsedSinceLastCycle + (2*$SLEEP_WAIT_QUANTUM)) -ge $TestInterval) { break }
		[console]::CursorVisible = $False
		$count = writeSpin $count
		Start-Sleep -Milliseconds $SLEEP_WAIT_QUANTUM
		Write-Host "`b" -NoNewLine
		[console]::CursorVisible = $True
	} while ( throwOnCtrlC )

	if ($timeLapsedSinceLastCycle -le $TestInterval) {
		$cycleStartTime = $cycleStartTime.Addmilliseconds($TestInterval)
	} else {
		$cycleStartTime = Get-Date
		if ($VerbosePreference) {
			Write-Warning "Unable to match requested test period, re-baselining cycle time."
		}
	}

	$timeStamp = $cycleStartTime | Get-Date -Format "HH:mm:ss"	
	Write-Host " ($timeStamp):" -NoNewLine

	# start all enabled tests
	foreach ($test in $tests) {
		if ($test.enabled) {				
			if ([string]::IsNullOrEmpty($test.dynargvar)) {
				$args = $test.args
			} else {
				$args = $test.args + $(get-variable -name $test.dynargvar -ValueOnly -ErrorAction SilentlyContinue)
			}
			$temp = Start-ThreadJob -ScriptBlock $test.code -ArgumentList $args -Name $test.name -ThrottleLimit $($enabled_tests+1)
			Write-Host "." -NoNewLine
		}
	}

	# give jobs time to actually start (not sure why, but this helps)
	# if checking job status here, before the sleep, actually all jobs are
	# still "NotStarted". It seems to take approx 100ms to start one job.
	Start-Sleep -Milliseconds $($enabled_tests*100) # auto-scale, 100ms per job

	$jobs = Get-Job
	$jobs | Out-String | Write-Debug
	$jobs | Wait-Job -Timeout $TIMEOUT_S > $null # NOTE: timeout <2s leads to sporadic errors (jobs are slow!)

	# check for debug purposes if there are still jobs running (i.e. late jobs)
	Get-Job -State Running | Out-String | Write-Debug

	# abort jobs that have not finished by now
	Get-Job -State Running | Stop-Job
	
	# consider this a complete cycle
	$Cycle++
	
	# check if user wants to abort (via Ctrl-c)
	$null = throwOnCtrlC	

	# statistics and housekeeping
	$LastCycleHadFail = $CycleHadFail
	$LastCycleHadWarning = $CycleHadWarning

	$jobStatistics = jobsEvalThenPurge
	$CycleHadFail = $jobStatistics.Fails
	$CycleHadWarning = $jobStatistics.Warnings
	
	$CyclesWithFail += $CycleHadFail
	$CyclesWithWarnings += $CycleHadWarning

	Write-Host "." -NoNewLine
	$null = throwOnCtrlC

	if (($Display -eq "Full") -or
		(($Display -eq "Warning") -and ($LastCycleHadFail -or $CycleHadFail -or $LastCycleHadWarning -or $CycleHadWarning)) -or
		(($Display -eq "Error") -and ($LastCycleHadFail -or $CycleHadFail)) -or
		($Cycle -le 1)) {
		Write-Host
	} else {
		clearCurrentConsoleLine
	}
		
	# TTL of the record is 30(s), rotate at TTL expiration to test DNS caching
	if ($DNSTestDynPrefix -ge $([Math]::Floor($(30000/$TestInterval-1)))) { $DNSTestDynPrefix = 0 } else { $DNSTestDynPrefix++ }
	
}} catch {
	Write-Debug "Entering catch statement after exception"
	Get-Job | Wait-Job -Timeout $TIMEOUT_S > $null
	Get-Job -State Running | Stop-Job

	# close out on started jobs
	
	$null = jobsEvalThenPurge
} finally {
	$programEndTime = Get-Date
	$programLength = [Math]::Round(($programEndTime - $programStartTime).Totalseconds,0)

	# notify we are stopping
	Write-Host " "
	Write-Host "Ending mon-con after $Cycle complete cycle(s), runtime was ~$programLength second(s)."

	# abort in orderly fashion
	$jobs = Get-Job
	if ($jobs) {
		Write-Host "Gathering last results from run #${CYCLE}: " -NoNewLine
		$results = Wait-Job -Timeout 0.1 -job $jobs
		# abort jobs that have not finished by now
		Get-Job | Stop-Job
		
		$null = jobsEvalThenPurge
		Write-Host ""
	}

	# safeguard to really have everything terminated
	Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue

	# generate and output summary stats
	Write-Host ""
	Write-Host "Test Results Summary:"
	foreach ($test in $tests) {
		if ($test.enabled) {
			$vname_fail = $test.Name + "_FAIL"
			$vname_pass = $test.Name + "_PASS"
			$vname_total = $test.Name + "_TOTAL"

			$temp_fail = get-variable -name "$vname_fail" -ValueOnly -ErrorAction SilentlyContinue
			$temp_pass = get-variable -name "$vname_pass" -ValueOnly -ErrorAction SilentlyContinue
			if ($temp_pass) {} else {$temp_pass = 0}

			$temp_total = $temp_fail + $temp_pass
			set-variable -name "$vname_total" -value $temp_total

			if ($temp_total -gt 0) {
				$temp_percent = [Math]::Round($temp_pass / $temp_total * 100, 2)
			} else {
				$temp_percent = "N/A"
			}
			$stuffChars=($test.name.Length -lt 12) ? 12-$test.name.Length : 0 
			Write-Host ($test.name + (' ' * $stuffChars) + ':') -NoNewLine
			if ($temp_fail -gt 1) {
				Write-Host $temp_percent% -NoNewLine -ForeGroundColor Red
			} elseif ($temp_fail -gt 0) {
				Write-Host $temp_percent% -NoNewLine -ForeGroundColor Yellow
			} else {
				Write-Host $temp_percent% -NoNewLine -ForeGroundColor Green
			}
			Write-Host " ($temp_pass/$temp_total)" -NoNewLine
			Write-Host "   pass% (passed/total)" -ForeGroundColor DarkGray
		} else {
			Write-Debug "$($test.Name) is disabled: No stats."
		}
	}

	# reset priority of the PowerShell
	(Get-Process -Id $PID).PriorityClass = $startupPriority

	# re-enable Ctrl-c
	[Console]::TreatControlCAsInput = $False

	Write-Host "Exiting."
}
