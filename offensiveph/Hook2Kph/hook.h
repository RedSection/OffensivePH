#pragma once

HANDLE __stdcall HOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

BOOL __stdcall HReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);

BOOL __stdcall HOpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

BOOL __stdcall HTerminateProcess(HANDLE hProcess, UINT uExitCode);

BOOL __stdcall HWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

HANDLE __stdcall HOpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);

BOOL __stdcall HTerminateThread(HANDLE hThread, DWORD dwExitCode);

BOOL __stdcall HGetThreadContext(HANDLE hThread, LPCONTEXT lpContext);

BOOL __stdcall HSetThreadContext(HANDLE hThread, LPCONTEXT lpContext);

BOOL __stdcall HDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
