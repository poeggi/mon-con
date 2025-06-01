# .\mon-con.ps1
## SYNOPSIS
MON(itor)-CON(nection), test and monitor your internet connection.

## SYNTAX
```powershell
.\mon-con.ps1 [-BeepOnError] [[-Display] <String>] [[-FocusTest] <String>] [[-Iterations] <Int32>] [-ListTests] [[-TestInterval] <Int32>] [[-Timeout] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
This powershell script does monitor a chain of interfaces / connections.
It has been developed and tested on Win 11, requires at least Powershell 7.

LOCAL-SYSTEM(PC)<->LAN<->ROUTER/GATEWAY<->INTERNET-UPLINK<->EXT.SERVER(S)

IPv4 and IPv6 are tested concurrently, assuming both are available.

From your local system, all the way up the the mighty internet, it tests
different intermediate hops and services. Theey are automatically determined
and/or preconfigured.
These tests should aid debugging an internet connection and help identify
the cause for spurious connectivity problems.

The script runs in the foreground, with cyclic information on the console.

There is a number of ping and DNS tests pre-defined and enabled.
Custom tests can be added easily.

Each test can either pass (green) or fail (red).  
Warnings (yellow) will be emitted in case of unusual or slow responses
(e.g. a ping tests RTT is high or DNS TTL is 0).

## PARAMETERS
### -BeepOnError &lt;SwitchParameter&gt;
Switch to enable acoustic feedback (beeping) for every test that failed.
```
Required?                    false
Position?                    named
Default value                False
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -Display &lt;String&gt;
Define [enum] how to scroll the output and which information to retain.  
Full    -> Retain all test lines, scroll after each test (Default)  
Warning -> Retain lines with Error or Warning  
Error   -> Retain only lines with Error  
Note: Output will also retain margin, i.e. one line before/after an event.
```
Required?                    false
Position?                    1
Default value                Full
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -FocusTest &lt;String&gt;
With this parameter, only the test named [string] is executed.
```
Required?                    false
Position?                    2
Default value
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -Iterations &lt;Int32&gt;
Define the [int] number of cycles that the test(s) will be run.  
Default is -1, i.e. infinitely (until CTRL-C is received).
```
Required?                    false
Position?                    3
Default value                -1
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -ListTests &lt;SwitchParameter&gt;
Switch to make the script print a list of available tests.
No test(s) will actually be run.
```
Required?                    false
Position?                    named
Default value                False
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -TestInterval &lt;Int32&gt;
Defines the [int] cycle time (in milliseconds) at which tests are repeated.  
Default is 3000(ms), i.e. 3 seconds.  
NOTE: in most setups, 3 (seconds) is the lowest usable value.
```
Required?                    false
Position?                    4
Default value                3000
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -Timeout &lt;Int32&gt;
The [int] time to wait for any individual test to complete, in milliseconds.
Default is 2000(ms), i.e. 2 seconds.  
NOTE: in most setups, 2 (seconds) is the lowest viable value.
```
Required?                    false
Position?                    5
Default value                2000
Accept pipeline input?       false
Accept wildcard characters?  false
```

## INPUTS
None. You can't pipe objects.

## OUTPUTS
Only Text (as this is a command-line live monitoring tool).

## NOTES
Author  : Kai Poggensee  
Version : 0.3 (2024-11-05) - Add WWAN / direct P2P connection support

## EXAMPLES
### EXAMPLE 1
```powershell
PS>.\mon-con.ps1 -BeepOnError -Display Warning -Timeout 2500 -Verbose
```


