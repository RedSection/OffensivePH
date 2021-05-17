#include "extract.h"
#include "resource.h"
#include <stdio.h>

DWORD ExtractDriver(LPWSTR lpFilePath) {
	LPCVOID lpBuffer;
	DWORD dwSize;
	DWORD dwBytesWritten;
	HRSRC hRes;
	HGLOBAL hGlob;
	hRes = FindResource(
		GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_FILE1), L"FILE");
	dwSize = SizeofResource(GetModuleHandle(NULL), hRes);
	hGlob = LoadResource(GetModuleHandle(NULL), hRes);
	lpBuffer = LockResource(hGlob);

	HANDLE hFile = CreateFile(lpFilePath, GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\n[-] Failed to open directory for writing: %d", GetLastError());
		goto Cleanup;
	}
	if (!WriteFile(hFile, lpBuffer, dwSize, &dwBytesWritten, NULL)) {
		printf("\n[-] Failed to write driver to the path: %d", GetLastError());
		goto Cleanup;
	}
	printf("\n[*] Driver path: %ws", lpFilePath);
	CloseHandle(hFile);
	return 0;

Cleanup:
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	return -1;
}
