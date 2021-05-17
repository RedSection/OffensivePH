#include "pch.h"
#include "extract.h"
#include "resource.h"
#include <stdio.h>

DWORD ExtractDriver(LPWSTR lpFilePath, HMODULE hModule) {
	LPCVOID lpBuffer;
	DWORD dwSize;
	DWORD dwBytesWritten;
	HRSRC hRes;
	HGLOBAL hGlob;
	hRes = FindResource(
		hModule, MAKEINTRESOURCE(IDR_FILE1), L"FILE");
	dwSize = SizeofResource(hModule, hRes);
	hGlob = LoadResource(hModule, hRes);
	lpBuffer = LockResource(hGlob);

	HANDLE hFile = CreateFile(lpFilePath, GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//MessageBoxA(HWND_DESKTOP, "\n[-] Failed to open directory for writing: %d", "error", MB_OK);
		goto Cleanup;
	}
	if (!WriteFile(hFile, lpBuffer, dwSize, &dwBytesWritten, NULL)) {
		//MessageBoxA(HWND_DESKTOP, "\n[-] Failed to write driver to the path: %d", "error", MB_OK);
		goto Cleanup;
	}
	CloseHandle(hFile);
	return 0;

Cleanup:
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	return -1;
}
