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
	This powershell script does monitor a chain of interfaces / connections.
	It has been developed and tested on Win 11, requires min. Powershell v7.

	LOCAL-SYSTEM(PC)<->LAN<->ROUTER/GATEWAY<->INTERNET-UPLINK<->EXT.SERVER(S)

	IPv4 and IPv6 are tested concurrently, assuming both are available.

	From your local system, all the way up the the mighty internet, it tests
	different intermediate hops and services. They are automatically determined
	and/or pre-configured in the script, can be overridden in a config file.
	These tests should aid debugging an internet connection and help identify
	the cause for spurious connectivity problems.

	The script runs in the foreground, cyclic updates printed to the console.

	There is a number of ping and DNS tests pre-defined and enabled.
	Custom tests can be added easily.

	Each test can either pass (green) or fail (red).  
	Warnings (yellow) will be emitted in case of unusual or slow responses
	(e.g. a ping tests RTT is high or DNS TTL is 0).  
	Timeouts are marked (blue).

	.PARAMETER BeepOnError
	Switch to enable acoustic feedback (beeping) for every test that failed.

	.PARAMETER Display
	Define [enum] how to scroll the output and which information to retain.  
	Full    -> Retain all test lines, scroll after each test (Default)  
	Warning -> Retain lines with Error or Warning  
	Error   -> Retain only lines with Error  
	Note: Output will also retain margin, i.e. one line before/after an event.

	.PARAMETER FocusTest
	With this parameter, only the test(s) named [string] is executed.
	Multiple tests can be defined, comma separated. Wildcards supported.

	.PARAMETER Iterations
	Define the [int] number of cycles that the test(s) will be run.  
	Default is -1, i.e. infinitely (until CTRL-C is received).

	.PARAMETER ListTests
	Switch to make the script print a list of available tests.
	No test(s) will actually be run.

	.PARAMETER TestInterval
	Defines the [int] cycle time (in milliseconds) at which tests are repeated.  
	Default is 3000(ms), i.e. 3 seconds.  
	NOTE: in most setups, 3 (seconds) is the lowest usable value.

	.PARAMETER Timeout
	The [int] time to wait for any individual test to complete, in milliseconds.
	Default is 2000(ms), i.e. 2 seconds.  
	NOTE: in most setups, 2 (seconds) is the lowest viable value.

	.INPUTS
	None. You can't pipe objects.

	.OUTPUTS
	Only Text (as this is a command-line live monitoring tool).

	.EXAMPLE
	PS> .\mon-con.ps1 -BeepOnError -Display Warning -Timeout 2500 -Verbose

	.NOTES
	Author  : Kai Poggensee  
	Version : 0.5 (2025-06-12) - introduce new DNS ping to optimize tests
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
	[string[]]$FocusTest,
	[Parameter()]
	[int]$Iterations = -1,
	[Parameter()]
	[switch]$ListTests,
	[Parameter()]
	[int]$TestInterval = 3000,
	[Parameter()]
	[int]$Timeout = 2000
)

#
# default configuration options (override via config file)
#

# The DNS server to use when doing DNS tests against a public DNS
$PUBLIC_DNS_SERVER_NAME = "one.one.one.one"

# The domain name (prefixed with a dynamic counter) to use for testing DNS
$DNS_TEST_DOMAIN = "lowttl.poggensee.it" # TTL 60(s) records for DNS testing

# Define the public host to use for external (ping) testing.
# NOTE: feasible choice is a host reachable always and everywhere, with HA
# Choose two hosts with one IP ODD the other EVEN, to test routing based LB
$EXT_TEST_HOST1 = "one.one.one.one"
$EXT_TEST_HOST2 = "security.cloudflare-dns.com"

# URLs where we can query the public IP of the host running this script
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
	[ipaddress]$OwnIPv4
	[ipaddress]$OwnIPv6
	[ipaddress]$OwnLLIPv6
	[ipaddress]$OwnPubIPv4
	[ipaddress]$OwnPubIPv6
	[ipaddress]$DefaultRouterIPv4
	[ipaddress]$DefaultRouterIPv6
	[ipaddress]$LocalDnsServerIPv4
	[ipaddress]$LocalDnsServerIPv6
	[string]$LocalDnsServerName
	[string]$PublicDnsServerName
	[ipaddress]$PublicDnsServerIPv4
	[ipaddress]$PublicDnsServerIPv6
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

New-Variable -Option Constant -Name IPv4_REGEXP -Value '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
New-Variable -Option Constant -Name IPv6_REGEXP -Value '^([0-9a-f]{0,4}|\:)*\:([0-9a-f]{0,4}|\:)*$'


#
# functions
#

function getDefaultRouteInterface {
	param (
		[Parameter(mandatory=$True)]
		$Proto
	)
	$InterfaceName = ""
	$Interface = ""
	$Metric = 1000
	
	$Interfaces = (Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.IPEnabled})
	foreach ($IF in $Interfaces) {
		$SubInterfaces = (Get-NetIPInterface -InterfaceIndex $IF.InterfaceIndex)

		if ($IF.ServiceName -eq "VBoxNetAdp") {
			Write-Debug "Skipping VirtualBox adapter and all sub-interfaces of '$($SubInterfaces[0].ifAlias)'"
			continue
		} elseif (!$IF.DefaultIPGateway) {
			Write-Debug "Skipping gateway-less adapter and all sub-interfaces of '$($SubInterfaces[0].ifAlias)'"
			continue
		}

		Write-Debug "Checking sub-interfaces of adapter '$($SubInterfaces[0].ifAlias)'"
		foreach ($SubIF in $SubInterfaces) {
			if ($SubIF.AddressFamily -eq $Proto) {
				if ($SubIF.InterfaceMetric -le $Metric) {
					$InterfaceName = $SubIF.ifAlias
					$Interface = $IF
					$Metric = $SubIF.InterfaceMetric
				}
			}
		}
	}
	Write-Verbose "Determined $($Proto) default route interface: '$InterfaceName' (#$($Interface.InterfaceIndex)), Metric: $Metric"
	
	return $Interface
}

function getLocalHostIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$IPv4Interface = getDefaultRouteInterface('IPv4')
		$IPs = $IPv4Interface.IPAddress
		foreach ($IP in $IPs) {
			if ($IP -match $IPv4_REGEXP) {
				$IPConfig.OwnIPv4 = $IP
			}
		}
		$IPv6Interface = getDefaultRouteInterface('IPv6')
		$IPs = $IPv6Interface.IPAddress
		foreach ($IP in $IPs) {
			if ($IP -match $IPv6_REGEXP) {
				if ($IP -match "fe80:*") {
					$IPConfig.OwnLLIPv6 = $IP;
				} else {
					$IPConfig.OwnIPv6 = $IP;
				}
			}
		}
	} catch {
		Write-Warning "Own local IPs could not be determined. Falling back to localhost addresses."
		$IPConfig.OwnIPv4 = "127.0.0.1"
		$IPConfig.OwnIPv6 = "::1"
		$IPConfig.OwnLLIPv6 = "::1"
	} finally {
		Write-Host "Local (Own) IPv4 address:" $IPConfig.OwnIPv4
		Write-Host "Local (Own) routeable IPv6 address:" $IPConfig.OwnIPv6
		Write-Host "Local (Own) LinkLocal IPv6 address:" $IPConfig.OwnLLIPv6
	}
}

function getHostPublicIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		# For IPv4 and IPv6 determine with the help of external server
		$IPConfig.OwnPubIPv4 = (Invoke-WebRequest $PUBLIC_IPv4_URL -ConnectionTimeoutSeconds 4 -OperationTimeoutSeconds 4).Content
		$IPConfig.OwnPubIPv6 = (Invoke-WebRequest $PUBLIC_IPv6_URL -ConnectionTimeoutSeconds 4 -OperationTimeoutSeconds 4).Content
	} catch {
		Write-Warning "Own public IPs could not be determined."
		# TODO: consider to fail gracefully?
	} finally {
		Write-Host "Hosts public IPv4 address:" $IPConfig.OwnPubIPv4
		Write-Host "Hosts public IPv6 address:" $IPConfig.OwnPubIPv6
	}
}

function getDefaultRouterIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	$IPv4Interface = getDefaultRouteInterface('IPv4')
	$IPv6Interface = getDefaultRouteInterface('IPv6')
	
	$IPv4Gateways = (Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.InterfaceIndex -eq $IPv4Interface.InterfaceIndex}| ?{$_.IPEnabled}).DefaultIPGateway
	foreach ($IPv4Gateway in $IPv4Gateways) {
		if ($IPv4Gateway -match $IPv4_REGEXP)
		{
			$IPConfig.DefaultRouterIPv4 = $IPv4Gateway
		}
	}

	$IPv6Gateways = (Get-wmiObject Win32_networkAdapterConfiguration | ?{$_.InterfaceIndex -eq $IPv6Interface.InterfaceIndex}| ?{$_.IPEnabled}).DefaultIPGateway
	foreach ($IPv6Gateway in $IPv6Gateways) {
		if ($IPv6Gateway -match $IPv6_REGEXP)
		{
			$IPConfig.DefaultRouterIPv6 = $IPv6Gateway
		}
	}
	
	Write-Host "Default IPv4 router:" $IPConfig.DefaultRouterIPv4
	Write-Host "Default IPv6 router:" $IPConfig.DefaultRouterIPv6
}

function getLocalDnsServerName {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$LocalDnsAutoDetected = (echo "exit" | nslookup.exe | Select-String -Pattern "^.*erver:.*" -CaseSensitive -Raw | Select-String -Pattern "[.:a-z0-9]*$" | % { $_.Matches } | % { $_.Value })		
		$IPConfig.LocalDnsServerName = $LocalDNSAutoDetected
	} catch {
		Write-Error "Local DNS server could not be determined."
		exit
	} finally {
		Write-Host "Determined Local DNS server name:" $IPConfig.LocalDnsServerName
	}
}

function getPublicDnsServerIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	$IPConfig.PublicDnsServerName = $PUBLIC_DNS_SERVER_NAME
	try {
		$IPConfig.PublicDnsServerIPv4 = Resolve-DnsName -QuickTimeout -type A "$PUBLIC_DNS_SERVER_NAME." |  Where-Object -Property Section -eq "Answer" |  Where-Object -Property Type -eq "A" | select -ExpandProperty IPAddress | Sort-Object -Property { [Version]$_ } | Select-Object -first 1
		$IPConfig.PublicDnsServerIPv6 = Resolve-DnsName -QuickTimeout -type AAAA "$PUBLIC_DNS_SERVER_NAME." | Where-Object -Property Section -eq "Answer" | Where-Object -Property Type -eq "AAAA" |  select -ExpandProperty IPAddress | Sort-Object -Property { [IPAddress]$_ } | Select-Object -first 1
	} catch {
		Write-Warning "Public DNS server not resolved. Falling back to DNS server name."
		$IPConfig.PublicDnsServerIPv4 = $PUBLIC_DNS_SERVER_NAME
		$IPConfig.PublicDnsServerIPv6 = $PUBLIC_DNS_SERVER_NAME
	} finally {
		Write-Host "Configured public DNS server:" $IPConfig.PublicDnsServerName
		Write-Host "Public DNS server IPv4 address:" $IPConfig.PublicDnsServerIPv4
		Write-Host "Public DNS server IPv6 address:" $IPConfig.PublicDnsServerIPv6
	}
}

function getLocalDnsServerIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$IPv4Interface = getDefaultRouteInterface('IPv4')
		$IPv6Interface = getDefaultRouteInterface('IPv6')

		$IPConfig.LocalDnsServerIPv4 = (get-DnsClientServerAddress -InterfaceIndex $IPv4Interface.InterfaceIndex | Where-Object -Property AddressFamily -eq "2").ServerAddresses[0]
		$IPConfig.LocalDnsServerIPv6 = (get-DnsClientServerAddress -InterfaceIndex $IPv6Interface.InterfaceIndex | Where-Object -Property AddressFamily -eq "23").ServerAddresses[0]
	} catch {
		Write-Warning "Local (IF config) DNS server not resolved. Falling back to DNS server name."
		$IPConfig.LocalDnsServerIPv4 = $IPConfig.LocalDnsServerName
		$IPConfig.LocalDnsServerIPv6 = $IPConfig.LocalDnsServerName
	} finally {
		Write-Host "Local (IF configured) DNS server IPv4 address:" $IPConfig.LocalDnsServerIPv4
		Write-Host "Local (IF configured) DNS server IPv6 address:" $IPConfig.LocalDnsServerIPv6
	}
}

function getAUXTestIPs {
	param (
		[Parameter(mandatory=$True)]
		[IPConfigClass]$IPConfig
	)
	try {
		$IPConfig.AUXAddrIPv4 = Resolve-DnsName -QuickTimeout -type A -DNSOnly -NoHostsFile "$AUX_TEST_HOST." | Where-Object -Property section -eq "Answer" | Where-Object -Property Type -eq "A" | select -ExpandProperty IPAddress | Sort-Object -Property { [Version]$_ } | Select-Object -last 1
		$IPConfig.AUXAddrIPv6 = Resolve-DnsName -QuickTimeout -type AAAA -DNSOnly -NoHostsFile "$AUX_TEST_HOST." | Where-Object -Property section -eq "Answer" | Where-Object -Property Type -eq "AAAA" | select -ExpandProperty IPAddress | Sort-Object -Property { [IPAddress]$_ } | Select-Object -last 1
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
		$IPConfig.PublicTestHost1AddrIPv4 = Resolve-DnsName -QuickTimeout -type A -DNSOnly -NoHostsFile "$EXT_TEST_HOST1." | Where-Object -Property Section -eq "Answer" | Where-Object -Property Type -eq "A" | select -ExpandProperty IPAddress | Sort-Object -Property { [Version]$_ } | Select-Object -last 1
		$IPConfig.PublicTestHost1AddrIPv6 = Resolve-DnsName -QuickTimeout -type AAAA -DNSOnly -NoHostsFile "$EXT_TEST_HOST1." | Where-Object -Property Section -eq "Answer" | Where-Object -Property Type -eq "AAAA" | select -ExpandProperty IPAddress | Sort-Object -Property { [IPAddress]$_ } | Select-Object -last 1
		$IPConfig.PublicTestHost2AddrIPv4 = Resolve-DnsName -QuickTimeout -type A -DNSOnly -NoHostsFile "$EXT_TEST_HOST2." | Where-Object -Property Section -eq "Answer" | Where-Object -Property Type -eq "A" | select -ExpandProperty IPAddress | Sort-Object -Property { [Version]$_ } | Select-Object -last 1
		$IPConfig.PublicTestHost2AddrIPv6 = Resolve-DnsName -QuickTimeout -type AAAA -DNSOnly -NoHostsFile "$EXT_TEST_HOST2." | Where-Object -Property Section -eq "Answer" | Where-Object -Property Type -eq "AAAA" | select -ExpandProperty IPAddress | Sort-Object -Property { [IPAddress]$_ } | Select-Object -last 1
	} catch {
		Write-Warning "Could not resolve IPs of public test hosts, falling back to names."
		$IPConfig.PublicTestHost1AddrIPv4 = $EXT_TEST_HOST1
		$IPConfig.PublicTestHost1AddrIPv6 = $EXT_TEST_HOST1
		$IPConfig.PublicTestHost2AddrIPv4 = $EXT_TEST_HOST2
		$IPConfig.PublicTestHost2AddrIPv6 = $EXT_TEST_HOST2
	} finally {
		Write-Host "Configured public server #1:" $EXT_TEST_HOST1
		Write-Host "Public Server #1 IPv4 address:" $IPConfig.PublicTestHost1AddrIPv4
		Write-Host "Public Server #1 IPv6 address:" $IPConfig.PublicTestHost1AddrIPv6
		Write-Host "Configured public server #2:" $EXT_TEST_HOST2
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
	
	# determine hosts public IP adresses
	getHostPublicIPs $IPConfig
	
	# determine local default routers
	getDefaultRouterIPs $IPConfig
	
	# determine DNS
	getPublicDnsServerIPs $IPConfig
	getLocalDnsServerIPs $IPConfig
	getLocalDnsServerName $IPConfig

	if (![string]::IsNullOrEmpty($AUX_TEST_HOST)) {
		# determine own AUX addresses
		getAUXTestIPs $IPConfig
	}

	# determine own Public test-host addresses
	getPublicTestIPs $IPConfig
}   

function throwOnCtrlC {
	while ([Console]::KeyAvailable) {
		$readKey = [Console]::ReadKey($True)
		if (($readKey.Modifiers -eq "Control") -and ($readKey.Key -eq "C")) {				
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
			
			$jobOutput = Receive-Job -job $job -Keep 2>&1
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
			$jobOutput = Receive-Job -job $job 2>&1
			if ($jobOutput -eq "") {
				$jobOutput = $job.Name + ": No output generated."
			}

			# output details of failure if verbose or always if debug
			if ($VerbosePreference -and $OutputJob) {
				Write-Verbose ""
				$jobOutput | Write-Verbose
			}
			elseif ($DebugPreference) {
				Write-Debug ""
				$jobOutput | Write-Debug
			}
		}

		Remove-Job -job $job
	}
	return @{fails=$fail; warnings=$warning}
}

function printTestInformationAsHelp {

	foreach ($test in $tests) {
		Write-Output ""
		Write-Output "Test Name:   $($test.name)"
		Write-Output "Description: $($test.descr)"
		if ($test.enabled) {
			Write-Output "(Test is currently ENabled)"
		} else {
			Write-Output "(Test is currently DISabled)"
		}
	}
	Write-Output ""
}

# 
# Generic test code definitions (used in the jobs the script spawns)
#

$SelftestDummyJobTestCode = {
	param (
		[Parameter(Position=0,mandatory=$True)]
		[string]$DEBUG_TESTOUTPUT
	)
	if($PSVersionTable.PSVersion.Major -lt 7) {
		Write-Output "Failed: PowerShell is not v7, how did we get here? Aborting."
		throw
	}
	if($PSVersionTable.PSVersion.Minor -lt 4) {
		Write-Output "Warning: PowerShell version is outdated, expect sub-par performance!"
	}
	Write-Output "Running PowerShell Version: $($PSVersionTable.PSVersion.ToString())"
	
	Write-Output "Starting Self-test job, total runtime 250ms."
	Write-Output "Sleeping 200ms..."
	Start-Sleep -Milliseconds 200
	Write-Output "Sleeping 50ms..."
	Start-Sleep -Milliseconds 50
	Write-Output "Parameter handed over for testing was: '$DEBUG_TESTOUTPUT'."
	Write-Output "Completing test with regular success status."
	return
}	

$DNSUDP_PingTestCode = {
    param (
		[Parameter(Position=0,mandatory=$True)]
		[int]$IPVER,
		[Parameter(Position=1,mandatory=$True)]
		[string]$TARGET,
		[Parameter(Position=2,mandatory=$True)]
		[int]$TIMEOUT_PING,
		[Parameter(Position=3,mandatory=$False)]
		[string]$DNSNAME
    )

    $udpClient = $null
	$success = $False
	Write-Output "DNS Ping preparing request towards $($TARGET) using IPv$($IPVER)"

    try {
        # Set address family
        $addrFamily = if ($IPVER -eq 6) {
            [System.Net.Sockets.AddressFamily]::InterNetworkV6
        } else {
            [System.Net.Sockets.AddressFamily]::InterNetwork
        }

		$remoteEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]$TARGET, 53)

		# Create UDP client and set timeout
		$udpClient = New-Object System.Net.Sockets.UdpClient($addrFamily)

        $targetAsInt=[bigint]::new(([System.Net.IPAddress]::Parse($TARGET).GetAddressBytes() + 0)) % 8192

		# Fixed local port to bind to (change if needed)
		$localPort = 40000 + $IPVER + $targetAsInt

		# Create local endpoint to bind socket (IPv4 or IPv6 Any)
		if ($addrFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
			$localEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::IPv6Any, $localPort)
		} else {
			$localEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, $localPort)
		}

		# Bind UDP client to fixed local port
		$udpClient.Client.Bind($localEP)

        $udpClient.Client.SendTimeout = $TIMEOUT_PING
        $udpClient.Client.ReceiveTimeout = $TIMEOUT_PING

        # create DNS query header

		$transactionId = [byte[]]@(
			[byte](Get-Random -Minimum 0 -Maximum 256),
			[byte](Get-Random -Minimum 0 -Maximum 256)
		)
		#$transactionId = [byte[]]@(([byte]0),([byte]$IPVER))

        $flags = 0x01, 0x00  # Standard query
        $questions = 0x00, 0x01
        $answerRRs = 0x00, 0x00
        $authorityRRs = 0x00, 0x00
        $additionalRRs = 0x00, 0x00

        if (-not $DNSNAME) {
			# Root as default (AVOID: may lead to spurious error (missing response) when using Google DNS)
			$queryName = 0x00
		} else {
			# Define the domain name string explicitly (as it's implied in your original line)
			$domainName = $DNSNAME

			# Initialize a dynamic list to store the bytes as we build them
			$byteList = [System.Collections.Generic.List[byte]]::new()

			# Split the domain name into its individual parts (labels)
			$parts = $domainName.Split('.')

			# Loop through each part of the domain name
			foreach ($part in $parts) {
				# Add the length of the current part as a byte
				$byteList.Add($part.Length)

				# Loop through each character of the part and add its byte value
				foreach ($char in $part.ToCharArray()) {
					$byteList.Add([byte][char]$char)
				}
			}

			# Add the final null (zero) byte to terminate the DNS name sequence
			$byteList.Add(0)

			# Convert the list to a fixed-size byte array, assigning it to $queryName
			$queryName = $byteList.ToArray()
		}

        # Query type: A for IPv4, AAAA for IPv6
        $queryType = if ($IPVER -eq 6) {
            0x00, 0x1C  # AAAA
        } else {
            0x00, 0x01  # A
        }

        $queryClass = 0x00, 0x01  # IN class

        $query = $transactionId + $flags + $questions + $answerRRs + $authorityRRs + $additionalRRs + $queryName + $queryType + $queryClass

		$bytesSent = $udpClient.Send($query, $query.Length, $remoteEP)
		Write-Output "Local Port used: $($udpClient.Client.LocalEndPoint.Port)"
		Write-Output "Sent $($bytesSent) bytes in raw data:"
		Write-Output "$query"

		$recvEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)

		$response = $udpClient.Receive([ref]$recvEP)

		if ($response) {
			$success = $True
			Write-Output "Received $($response.length) bytes in raw data:"
			Write-Output "$response"
		}
    }
    catch {
		$success = $False
		Write-Output "Failure: DNS ping function threw an exception, details (if any) below."
		Write-Output $_.Exception.Message
    }
    finally {
        if ($udpClient) { $udpClient.Close() }
		if (-not $success) { throw "Failed DNS ping test" }
    }
}

$DNSTestCode = {
	param (
		[Parameter(Position=0,mandatory=$True)]
		[string]$DNS_RECORD_TYPE,
		[Parameter(Position=1,mandatory=$True)]
		[string]$DNS_SERVER,
		[Parameter(Position=2,mandatory=$False)]
		[bool]$OPT_NOREC = $False,
		[Parameter(Position=3,mandatory=$True)]
		[string]$TARGET
	)
	# NOTE: appending a "." to the TARGET if needed, to resolve only FQDN
	if (($DNS_RECORD_TYPE -notmatch '^A{1}A{0,3}$') -or ($TARGET -match '\.$')) {
		$TargetFQDN = $TARGET
	} else {
		$TargetFQDN = "${TARGET}."
	}

	Write-Output "Trying to Resolve $($DNS_RECORD_TYPE) of $($TargetFQDN) via $($DNS_SERVER)"
	if ($OPT_NOREC) {
		$output = Resolve-DnsName -type $DNS_RECORD_TYPE -server $DNS_SERVER -DNSOnly -NoHostsFile -NoRecursion -QuickTimeout -Name $TargetFQDN	2> $error
	} else {
		$output = Resolve-DnsName -type $DNS_RECORD_TYPE -server $DNS_SERVER -DNSOnly -NoHostsFile -QuickTimeout -Name $TargetFQDN 2> $error
	}

	if ($?) {
		$result = $output | Where-Object -Property Type -eq "$DNS_RECORD_TYPE" | Where-Object -Property Section -eq "Answer"
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
		$matches="" #initialize empty to avoid null array index error on no match
		(($output | Select-String -Pattern "[=<].*ms$" -Raw) -match "[=<]\s?([0-9]{1,5})ms$") > $null
		if ([bool]$matches[1]) {
			$RTT=[int]$matches[1]
		} else {
			$RTT=-1
		}
		
		# match 0 packets in '(0% loss', in a language agnostic way, also check if we have a RTT
		if (("$output" -match '\(0\%') -and ($RTT -ge 0)) {
			$success = $True

			# Assumption: RTT can be 100ms+, even for LAN, but even WAN shall not exceed 500ms
			if ($RTT -ge $(100 + ($OPT_MAXHOPS * 2))) {
				Write-Output "Warning: Ping RTT (round trip time) abnormally high: ${RTT}ms."
				$warn = $True
			}
		} else {
			Write-Output "Failure: Ping request sent but response missing (or after timeout of ${TIMEOUT_PING}s)."
			$success = $False
		}
	} else {
		Write-Output "Failure: Ping command returned an error, details from command (if any) below."
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

# take note of the script start time
$timeStamp = Get-Date -Format "HH:mm:ss"	
Write-Host "($timeStamp): Starting up mon-con"

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
		descr='DNS (recursive) resolve public "A" record via public DNS server, using IPv4';
		code=$DNSTestCode;
		args=('A', $IPConfig.PublicDnsServerIPv4.IPAddressToString, [bool]0);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True;
	}
	[TestClass]@{
		name='D6-PUB';
		descr='DNS (recursive) resolve public "AAAA" record via public DNS server, using IPv6';
		code=$DNSTestCode;
		args=('AAAA', $IPConfig.PublicDnsServerIPv6.IPAddressToString, [bool]0);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True;
	}
	[TestClass]@{
		name='D4-EXT';
		descr='DNS (recursive) resolve public "A" record via local (IF config) DNS, using IPv4';
		code=$DNSTestCode;
		args=('A', $IPConfig.LocalDnsServerIPv4.IPAddressToString, [bool]0);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True;
	}
	[TestClass]@{
		name='D6-EXT';
		descr='DNS (recursive) resolve public "AAAA" record via local (IF config) DNS, using IPv6';
		code=$DNSTestCode;
		args=('AAAA', $IPConfig.LocalDnsServerIPv6.IPAddressToString, [bool]0);
		dynargvar='SHORT_TTL_DNSTEST_HOST';
		enabled=$True;
	}
	[TestClass]@{
		name='D4-PGE';
		descr='DNS ping ext, send single-UDP-packet query and wait for any reply, using IPv4';
		code=$DNSUDP_PingTestCode;
		args=('4', $IPConfig.PublicDnsServerIPv4.IPAddressToString, $Timeout, $IPConfig.PublicDnsServerName);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='D6-PGE';
		descr='DNS ping ext, send single-UDP-packet query and wait for any reply, using IPv6';
		code=$DNSUDP_PingTestCode;
		args=('6', $IPConfig.PublicDnsServerIPv6.IPAddressToString, $Timeout, $IPConfig.PublicDnsServerName);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='D4-PIE'; # NOTE: Should be possible non-recursive, but Cloudflare generates spurious server errors if set, so allow recursion for now
		descr='DNS query from public DNS the "PTR" of his own IP, via IPv6';
		code=$DNSTestCode;
		args=('PTR', $IPConfig.PublicDnsServerIPv4.IPAddressToString, [bool]0, $IPConfig.PublicDnsServerIPv4.IPAddressToString);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='D6-PIE'; # NOTE: Should be possible non-recursive, but Cloudflare generates spurious server errors if set, so allow recursion for now
		descr='DNS query from public DNS the "PTR" of his own IP, via IPv6';
		code=$DNSTestCode;
		args=('PTR', $IPConfig.PublicDnsServerIPv6.IPAddressToString, [bool]0, $IPConfig.PublicDnsServerIPv6.IPAddressToString);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='D4-NRE';
		descr='DNS query from public DNS root "NS" records (implicitlty non-recursive), via IPv4';
		code=$DNSTestCode;
		args=('NS', $IPConfig.PublicDnsServerIPv4.IPAddressToString, [bool]0, '.');
		dynargvar='';
		enabled=$False; # NOTE: Google's public DNS is sometimes not answering, so test is disabled for now 
	}
	[TestClass]@{
		name='D6-NRE';
		descr='DNS query from public DNS root "NS" records (implicitlty non-recursive), via IPv6';
		code=$DNSTestCode;
		args=('NS', $IPConfig.PublicDnsServerIPv6.IPAddressToString, [bool]0, '.');
		dynargvar='';
		enabled=$False; # NOTE: Google's public DNS is sometimes not answering, so test is disabled for now 
	}
	[TestClass]@{
		name='D4-NRI';
		descr='DNS resolve (no-recurse) from local (IF config) DNS its own "PTR" record, via IPv4';
		code=$DNSTestCode;
		args=('PTR', $IPConfig.LocalDnsServerIPv4.IPAddressToString, [bool]1, $IPConfig.LocalDnsServerIPv4.IPAddressToString);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='D6-NRI';
		descr='DNS resolve (no-recurse) from local (IF config) DNS its own "PTR" record, via IPv6';
		code=$DNSTestCode;
		args=('PTR', $IPConfig.LocalDnsServerIPv6.IPAddressToString, [bool]1, $IPConfig.LocalDnsServerIPv6.IPAddressToString);
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
		name='P4-LIN';
		descr='Ping a host on the same link (local) via IPv4';
		code=$PingTestCode;
		args=('4', $IPConfig.DefaultRouterIPv4, 1, $Timeout);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='P6-LIN';
		descr='Ping a host on the same link (local) via IPv6';
		code=$PingTestCode;
		args=('6', $IPConfig.DefaultRouterIPv6, 1, $Timeout);
		dynargvar='';
		enabled=$True;
	}
	[TestClass]@{
		name='P4-LOC';
		descr='Ping this systems assinged local interface IPv4 address';
		code=$PingTestCode;
		args=('4', $IPConfig.OwnIPv4, 1, $Timeout);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='P6-LOC';
		descr='Ping this systems assinged local interface IPv6 address';
		code=$PingTestCode;
		args=('6', $IPConfig.OwnIPv6, 1, $Timeout);
		dynargvar='';
		enabled=$False;
	}
	[TestClass]@{
		name='ST';
		descr='SelfTest the PowerShell jobs system with a dummy job';
		code=$SelftestDummyJobTestCode;
		args=("FooBar");
		dynargvar='';
		enabled=$True	
	}
)

# focus test mode, disabling all other tests
if ($FocusTest) {
	$focusTestArray = $FocusTest -split ','
	foreach ($test in $tests) {
		$test.enabled = $false
		foreach ($pattern in $focusTestArray) {
			if ($test.name -like $pattern) {
				$test.enabled = $true
				break
			}
		}
	}
}

# Output list of active tests and purpose in verbose mode
$enabled_tests=0
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

$cycleStartTime = $testStartTime = Get-Date
$cycleStartTime = $cycleStartTime.AddMilliseconds(-$TestInterval)
$cycleStartTime = $cycleStartTime.AddMilliseconds(2*$SLEEP_WAIT_QUANTUM)

if ($ListTests) {
	printTestInformationAsHelp
	exit
}

# main loop
try {
while (($Iterations -le 0) -or ($Cycle -lt $Iterations))
	{
	$stuffChars = ($Cycle.ToString().Length -lt 5) ? 5-$Cycle.ToString().Length : 0

	# NOTE: dedicated DNS names, entries design to have a very low TTL 
	#	   as to not measure cache, but ensure external requests every time
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
		
	# TTL of the record is 60(s), rotate same speed to test DNS caching
	# as a result of this, the TTL received should never be <60s
	if ($DNSTestDynPrefix -ge $([Math]::Ceiling($((60000/$TestInterval)-1)))) {
		$DNSTestDynPrefix = 0
	} else {
		$DNSTestDynPrefix++
	}
	
}} catch {
	$timeStamp = Get-Date -Format "HH:mm:ss"	
	Write-Debug "($timeStamp): Entering catch statement after exception"
	Get-Job | Wait-Job -Timeout $TIMEOUT_S > $null
	Get-Job -State Running | Stop-Job

	# close out on started jobs
	
	$null = jobsEvalThenPurge

} finally {
	$testEndTime = Get-Date
	$testLength = [Math]::Round(($testEndTime - $testStartTime).Totalseconds,0)

	# notify we are stopping
	$timeStamp = $testEndTime | Get-Date -Format "HH:mm:ss"	

	Write-Host " "
	Write-Host "($timeStamp): Concluding tests after $Cycle test cycle(s) taking ~$testLength second(s)."

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
