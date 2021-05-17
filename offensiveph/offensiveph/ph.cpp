#include "phuser.h"

NTSTATUS PhOpenProcess(PHANDLE phProc, DWORD pid) {
	CLIENT_ID clientId;
	NTSTATUS status;
	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = NULL;
	return KphOpenProcess(phProc, PROCESS_ALL_ACCESS, &clientId);
}

NTSTATUS PhOpenThread(PHANDLE phThread, DWORD tid) {
	CLIENT_ID clientId;
	NTSTATUS status;
	clientId.UniqueProcess = NULL;
	clientId.UniqueThread = (HANDLE)tid;
	return KphOpenThread(phThread, THREAD_ALL_ACCESS, &clientId);
}

