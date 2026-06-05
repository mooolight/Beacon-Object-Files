#pragma once

#include "pers-runkeys-structs.h"

#pragma comment(lib, "Advapi32.lib")

#ifdef BOF
    #include "..\beacon.h"

    WINADVAPI LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,const LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY,LPCSTR,DWORD,DWORD,const BYTE *,DWORD);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExW(HKEY ,LPCWSTR ,REGSAM ,DWORD);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExA(HKEY ,LPCSTR ,REGSAM ,DWORD);
	
    #define RegCreateKeyExA     ADVAPI32$RegCreateKeyExA
    #define RegSetValueExA      ADVAPI32$RegSetValueExA
    #define RegCloseKey         ADVAPI32$RegCloseKey
    #define RegDeleteKeyExW     ADVAPI32$RegDeleteKeyExW
    #define RegOpenKeyExA       ADVAPI32$RegOpenKeyExA
    #define RegDeleteKeyExA     ADVAPI32$RegDeleteKeyExA
    
    #define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else
	#define PRINT(...)  printf(__VA_ARGS__);
#endif