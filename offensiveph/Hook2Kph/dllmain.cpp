// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "detours.h"
#include "extract.h"
#include "hook.h"

#pragma comment(lib, "detours.lib")

#define SERVICENAME L"kphsrv"
#define DRVPATH L"\\kph.sys"

DWORD SetupDriver(HMODULE hModule) {
	DWORD status;
	WCHAR lpServiceName[] = SERVICENAME;
	WCHAR lpFilePath[MAX_PATH] = { 0 };
	GetCurrentDirectory(MAX_PATH, lpFilePath);
	wcscat_s(lpFilePath, DRVPATH);
	status = ExtractDriver(lpFilePath, hModule);
	if(!NT_SUCCESS(KphConnect2Ex(lpServiceName, lpFilePath))) {
		return -1;
	}
	return 0;
}

NTSTATUS HookMeKph() {
	HMODULE hModule = GetModuleHandle(L"kernelbase.dll");

	//Get Winapi function addresses to hook
	LPVOID pOpenProcess = GetProcAddress(hModule, "OpenProcess");
	LPVOID pReadProcessMemory = GetProcAddress(hModule, "ReadProcessMemory");
	LPVOID pOpenProcessToken = GetProcAddress(hModule, "OpenProcessToken");
	LPVOID pTerminateProcess = GetProcAddress(hModule, "TerminateProcess");
	LPVOID pWriteProcessMemory = GetProcAddress(hModule, "WriteProcessMemory");
	LPVOID pOpenThread = GetProcAddress(hModule, "OpenThread");
	LPVOID pTerminateThread = GetProcAddress(hModule, "TerminateThread");
	LPVOID pGetThreadContext = GetProcAddress(hModule, "GetThreadContext");
	LPVOID pSetThreadContext = GetProcAddress(hModule, "SetThreadContext");
	LPVOID pDuplicateHandle = GetProcAddress(hModule, "DuplicateHandle");

	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	
	//Hook functions with detours 
	DetourAttach(&pOpenProcess, HOpenProcess);
	DetourAttach(&pReadProcessMemory, HReadProcessMemory);
	DetourAttach(&pOpenProcessToken, HOpenProcessToken);
	DetourAttach(&pTerminateProcess, HTerminateProcess);
	DetourAttach(&pWriteProcessMemory, HWriteProcessMemory);
	DetourAttach(&pOpenThread, HOpenThread);
	DetourAttach(&pTerminateThread, HTerminateThread);
	DetourAttach(&pGetThreadContext, HGetThreadContext);
	DetourAttach(&pSetThreadContext, HSetThreadContext);
	DetourAttach(&pDuplicateHandle, HDuplicateHandle);


	DetourAttach(&pOpenProcess, HOpenProcess);
	DetourAttach(&pReadProcessMemory, HReadProcessMemory);
	LONG lError = DetourTransactionCommit();
	if (lError != NO_ERROR) {
		//MessageBox(HWND_DESKTOP, L"Failed to detour", L"detour", MB_OK);
		return FALSE;
	}
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (DetourIsHelperProcess()) { return TRUE; }
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if (SetupDriver(hModule) != 0) break;
		HookMeKph();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		//Clean driver service if process is terminating
		if (lpReserved != NULL) {
			WCHAR lpServiceName[] = SERVICENAME;
			KphUninstall(lpServiceName);
		}
		break;
	}
	return TRUE;
}