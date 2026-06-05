#pragma once

#include "windef-disable-bof-structs.h"

#ifdef BOF
	#include "..\beacon.h"

	// Kernel32 imports
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
	DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

	#define GetCurrentProcess	KERNEL32$GetCurrentProcess
	#define CloseHandle			KERNEL32$CloseHandle

	// Advapi32 imports
	WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE,DWORD,PHANDLE);
	WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID, DWORD, PDWORD);
	WINADVAPI LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
	WINADVAPI LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY,LPCSTR,DWORD,DWORD,const BYTE *,DWORD);
	WINADVAPI LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,const LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
	WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);

	#define OpenProcessToken	ADVAPI32$OpenProcessToken
	#define GetTokenInformation	ADVAPI32$GetTokenInformation
	#define RegOpenKeyExA		ADVAPI32$RegOpenKeyExA
	#define RegSetValueExA		ADVAPI32$RegSetValueExA
	#define RegCreateKeyExA		ADVAPI32$RegCreateKeyExA
	#define RegCloseKey			ADVAPI32$RegCloseKey

	#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else

	#define PRINT(...)  printf(__VA_ARGS__);

#endif
