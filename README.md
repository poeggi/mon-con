# mon-con.ps1
## SYNOPSIS
MON(itor)-CON(nection) is a script to test and monitor your inet connection.

## SYNTAX
```powershell
mon-con.ps1 [-BeepOnError] [[-Display] <String>] [[-TestInterval] <Int32>] [[-Timeout] <Int32>] [[-FocusTest] <String>] [[-Iterations] <Int32>] [<CommonParameters>]
```

## DESCRIPTION
This script does monitor the complete chain of interfaces and connections,
i.e. DEV<->LAN<->ROUTER<->INTERNET<->Ext.SERVER, IPv4 and IPv6, concurrently 
From your local system all the way up the the mighty internet it tests
different intermediate hops, that are automatically determined.
It runs in the foreground and cyclically generates information.

There is a number of Ping and DNS tests already defined and enabled.
Each test can either pass or fail. 
Note: ping tests emit a warning if RTT is high, DNS if the TTL is 0.

## PARAMETERS
### -BeepOnError &lt;SwitchParameter&gt;
Give an acoustic feedback (beeping) for every test that failed.
```
Required?                    false
Position?                    named
Default value                False
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -Display &lt;String&gt;
Define how to scroll the output and which information to retain.
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
 
### -TestInterval &lt;Int32&gt;
Defines the cycle time (in milliseconds) at which the script repeats tests.
Default is 3000(ms), i.e. 3 seconds.
NOTE: in most setups, 3 (seconds) is the lowest usable value.
```
Required?                    false
Position?                    2
Default value                3000
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -Timeout &lt;Int32&gt;
The time to wait for any individual test to complete, in milliseconds.
Default is 2000(ms), i.e. 2 seconds.
NOTE: in most setups, 2 (seconds) is the lowest viable value.
```
Required?                    false
Position?                    3
Default value                2000
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -FocusTest &lt;String&gt;
With this parameter only the Test named [string] is executed.
Also, all of the tests output is being piped and made visible to the user.
```
Required?                    false
Position?                    4
Default value
Accept pipeline input?       false
Accept wildcard characters?  false
```
 
### -Iterations &lt;Int32&gt;
Define the [int] number of cycles that the test will run.
```
Required?                    false
Position?                    5
Default value                -1
Accept pipeline input?       false
Accept wildcard characters?  false
```

## INPUTS
None. You can't pipe objects.

## OUTPUTS
Only Text (as this is a monitoring tool).

## NOTES
Author   : Kai P.
Version  : 0.11 (2024-09-18) Initial Release (fixed)

## EXAMPLES
### EXAMPLE 1
```powershell
PS>.\mon-con.ps1 -BeepOnError -Display Warning -Timeout 2500 -Verbose
```


