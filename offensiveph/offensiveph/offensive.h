#pragma once
#include "base.h"
#include "kphapi.h"
#include "kphuser.h"
#include "phuser.h"
#include <iostream>
DWORD OphTerminateProcessByName(wchar_t* pName);
DWORD OphTerminateProcess(DWORD pid);
DWORD OphSuspendProcess(DWORD pid);
DWORD OphResumeProcess(DWORD pid);
DWORD OphReadVirtualMemory(DWORD pid, PVOID lpBaseAddress, SIZE_T nSize);
DWORD OphReadProcessPEB(DWORD pid);
DWORD OphWriteVirtualMemory(DWORD pid, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize);
DWORD OphImpersonateToken(DWORD pid);
DWORD OphDuplicateProcessToken(DWORD pid, PHANDLE phToken);
DWORD OphDuplicateProcessTokenImp(DWORD pid, PHANDLE phToken);
DWORD OphModifyThreadToken(DWORD tid, HANDLE hToken);
DWORD OphQueryProtectionProcess(DWORD pid);
DWORD OphQueryExecuteFlagsProcess(DWORD pid);
DWORD OphGetContextThread(DWORD tid);
DWORD OphDuplicateHandle(HANDLE hProc, HANDLE hObj, PHANDLE hLocalObj);
DWORD OphCloseRemoteHandle(HANDLE hProc, HANDLE hObj);
DWORD OphProtectObject(HANDLE hProc, HANDLE hObj);
DWORD OphCreateProtectedProcess(PHANDLE phProc);
DWORD OphCreateProtectedProcessWithToken(PPROCESS_INFORMATION ppi, HANDLE hToken);
DWORD OphHijackThread(DWORD pid, LPWSTR url);
DWORD OphEarlyBirdAPCInjection(LPWSTR url);

