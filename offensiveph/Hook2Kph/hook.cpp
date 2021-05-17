#include "pch.h"
#include "hook.h"

//Detour function definitions used for mapping winapi calls to Kph 

HANDLE WINAPI HOpenProcess(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
) {
	//MessageBox(HWND_DESKTOP, L"OpenProcess is called and hooked", L"detour", MB_OK);
	HANDLE ProcessHandle;
	CLIENT_ID ClientId = { 0 };
	ClientId.UniqueProcess = (HANDLE)dwProcessId;
	KphOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ClientId);
	return ProcessHandle;
}

BOOL WINAPI HReadProcessMemory(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
) {
	//MessageBox(HWND_DESKTOP, L"ReadProcessMemory is called and hooked", L"detour", MB_OK);
	if (!NT_SUCCESS(KphReadVirtualMemory(hProcess, (PVOID)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)))
		return FALSE;
	else
		return TRUE;
}

BOOL WINAPI HOpenProcessToken(
	HANDLE  ProcessHandle,
	DWORD   DesiredAccess,
	PHANDLE TokenHandle
) {
	if (!NT_SUCCESS(KphOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle)))
		return FALSE;
	else
		return TRUE;
}

BOOL WINAPI HTerminateProcess(
	HANDLE hProcess,
	UINT   uExitCode
) {
	if (!NT_SUCCESS(KphTerminateProcess(hProcess, uExitCode)))
		return FALSE;
	else
		return TRUE;
}

BOOL WINAPI HWriteProcessMemory(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
) {
	if (!NT_SUCCESS(KphWriteVirtualMemory(hProcess, (PVOID)lpBaseAddress,
		(PVOID)lpBuffer, nSize, lpNumberOfBytesWritten)))
		return FALSE;
	else
		return TRUE;
}

HANDLE WINAPI HOpenThread(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
) {
	HANDLE hThread;
	CLIENT_ID clientId;
	clientId.UniqueThread = (HANDLE)dwThreadId;
	KphOpenThread(&hThread, dwDesiredAccess, &clientId);
	return hThread;
}

BOOL WINAPI HTerminateThread(
	HANDLE hThread,
	DWORD  dwExitCode
) {
	if (!NT_SUCCESS(KphTerminateThread(hThread, dwExitCode)))
		return FALSE;
	else
		return TRUE;
}

BOOL WINAPI HGetThreadContext(
	HANDLE    hThread,
	LPCONTEXT lpContext
) {
	if (!NT_SUCCESS(KphGetContextThread(hThread, lpContext)))
		return FALSE;
	else
		return TRUE;
}

BOOL WINAPI HSetThreadContext(
	HANDLE    hThread,
	LPCONTEXT lpContext
) {
	if (!NT_SUCCESS(KphSetContextThread(hThread, lpContext)))
		return FALSE;
	else
		return TRUE;
}

BOOL WINAPI HDuplicateHandle(
	HANDLE   hSourceProcessHandle,
	HANDLE   hSourceHandle,
	HANDLE   hTargetProcessHandle,
	LPHANDLE lpTargetHandle,
	DWORD    dwDesiredAccess,
	BOOL     bInheritHandle,
	DWORD    dwOptions
) {
	if (!NT_SUCCESS(KphDuplicateObject(hSourceProcessHandle, hSourceHandle,
		hTargetProcessHandle, lpTargetHandle, dwDesiredAccess,
		bInheritHandle, dwOptions)))
		return FALSE;
	else
		return TRUE;
}
