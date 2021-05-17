#include <Windows.h>
#include <TlHelp32.h>
#include "thread.h"

DWORD GetThreadIdFromPID(DWORD pid) {
	HANDLE snapshot;
	THREADENTRY32 threadEntry;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	threadEntry.dwSize = sizeof(THREADENTRY32);
	Thread32First(snapshot, &threadEntry);

	while (Thread32Next(snapshot, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == pid)
		{
			return threadEntry.th32ThreadID;
		}
	}
	return threadEntry.th32ThreadID;

}