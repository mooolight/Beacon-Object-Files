#pragma once

#include "eva-sysmon-unload-bof-structs.h"

#ifdef BOF
	#include "..\beacon.h"
	#include "..\bofdefs.h"

	// Kernel32
	WINBASEAPI 		DWORD 	WINAPI KERNEL32$GetLastError(VOID);
	#define GetLastError KERNEL32$GetLastError
	DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess();
	#define GetCurrentProcess KERNEL32$GetCurrentProcess


	// Advapi32
	WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE,DWORD,PHANDLE);
	#define OpenProcessToken ADVAPI32$OpenProcessToken
	WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR ,LPCSTR ,PLUID);
	#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
	WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
	#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges

	#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else
	#define PRINT(...)  printf(__VA_ARGS__);
#endif
