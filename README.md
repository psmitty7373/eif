# eif - Evil Inject Finder
##Introduction
The eif tool is designed to help you find evil injected malware.  Malware injected directly into a process using reflective dll injection typically will not exist on disk.  This tool is designed to help you find those evil injections!  Administrative rights are currently necessary to adequately examine the memory of running processes.  Some memory pages will be unreadable if marked as protected processes by the OS.
##Examples
The example below demonstrates using eif with a signatures file to find injects in all processes on the system.  A meterpreter has been loaded into MicrosoftEdge using reflective injection.
```
C:\Users\IEUser\Desktop>EvilInjectFinder.exe -s sigs.txt -S

Analysing PID: 3908 : MicrosoftEdgeCP.exe
+---------------------------------------------------------------------------------------------------------------------------------------------------------+
|      Address | Permissions       |          Size | Module                                  | MZ  | DOS | Nops | Sigs | MD5                              |
+---------------------------------------------------------------------------------------------------------------------------------------------------------+
|       480000 | EXECUTE_READWRITE |        1.14MB |                                         | No  | Yes |   0% |    5 | 6CE6C24391C37E0D4883DBA14F04EA31 |
|  1dc06950000 | EXECUTE_READWRITE |      156.00KB |                                         | Yes | Yes |   0% |    3 | AC46BC374B6CD85D3564A3F5F62B92C1 |
|  1dc06990000 | EXECUTE_READWRITE |      436.00KB |                                         | Yes | Yes |   0% |    8 | 13CA507C4B0A15775ABCE144B7D8C4C4 |
|  1dc07590000 | EXECUTE_READWRITE |        1.18MB |                                         | Yes | Yes |   0% |    5 | A81939E4335F18FF2213032100411659 |
+---------------------------------------------------------------------------------------------------------------------------------------------------------+
```

##Usage
```
USAGE: example [options]

Options:
  -h               Print usage and exit.
  -b               Only show matches without .dll backing.
  -d               Use kernel driver to access protected process memory.
  -f <format>      Output format (CSV,).
  -i               Search pages with specific permissions. Default is
                   EXECUTE_READWRITE.
  -s <sigfile.txt> Use a signature file.
  -S               Only show memory pages with signature matches.
  -p               Specify a single PID.
  -w <c:\outdir\>  Write matching pages to disk.

Examples:
  eif.exe -p 123 -s sigs.txt -S -b -i EXECUTE_READWRITE

Available Permissions: EXECUTE, EXECUTE_READ, EXECUTE_READWRITE,
EXECUTE_WRITECOPY, NOACCESS, READWRITE, WRITECOPY, READONLY
```
##Signatures
Eif can search memory pages based on a signatures file.  Currently, this is a very simplistic string match search but is effective.  An example signatures file is below:
```
WSASTARTUP
WSADuplicateSocketA
WSACreateEvent
WSAEventSelect
WSASocketA
URLDownloadToCacheFileW
InternetCrackUrlA
InternetOpenA
InternetQueryOptionA
RevertToSelf
OpenProcessToken
CheckTokenMembership
GetTokenInformation
AdjustTokenPrivileges
HttpOpenRequestA
HttpSendRequestA
HttpQueryInfoA
ShellExecuteExW
ReflectiveLoader
AesCryptoServiceProvider
Invoke-Empire
RSACryptoServiceProvider
```
