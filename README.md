# ProcLogonId

## Usage

```
> .\ProcLogonId.exe
PID       ProcessName                                       SessionID  LogonId (H L)      User
--------  ------------------------------------------------  ---------  -----------------  --------
       0  FAILED: OpenProcess: 87
       4  FAILED: OpenProcess: 5
      88  FAILED: OpenProcess: 5
     152  FAILED: OpenProcess: 5
     620  FAILED: OpenProcess: 5
     932  FAILED: OpenProcess: 5
    1220  FAILED: OpenProcess: 5
    1228  FAILED: OpenProcess: 5
    1316  FAILED: OpenProcess: 5
    1336  -                                                 0          00000000 000003E7  NT AUTHORITY\SYSTEM
    1344  -                                                 0          00000000 000003E7  NT AUTHORITY\SYSTEM
    1436  -                                                 1          00000000 000003E7  NT AUTHORITY\SYSTEM
    1552  -                                                 0          00000000 000003E7  NT AUTHORITY\SYSTEM
    1588  -                                                 0          00000000 000003E5  NT AUTHORITY\LOCAL SERVICE
    1636  -                                                 1          00000000 00021BA4  Font Driver Host\UMFD-1
    1632  -                                                 0          00000000 00021BA3  Font Driver Host\UMFD-0
    1716  -                                                 0          00000000 000003E4  NT AUTHORITY\NETWORK SERVICE
    1764  -                                                 0          00000000 000003E7  NT AUTHORITY\SYSTEM
    1840  -                                                 0          00000000 000003E4  NT AUTHORITY\NETWORK SERVICE
    1928  FAILED: OpenProcess: 5
    1960  -                                                 0          00000000 000003E5  NT AUTHORITY\LOCAL SERVICE
    2020  -                                                 1          00000000 0002A308  Window Manager\DWM-1

...snip...
```

## Building from source

Run the **nmake** in the Visual Studio's Developer PowerShell or Developer Command Prompt.

```
nmake build
```
