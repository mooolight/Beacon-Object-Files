#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#ifdef BOF

#include "..\beacon.h"
// 
// Kernel32
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD ,DWORD);  // Nt equivalent == 
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);  // Nt equivalent == 
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);  // Nt equivalent == 
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);  // Nt equivalent == 

#define CreateToolhelp32Snapshot  KERNEL32$CreateToolhelp32Snapshot
#define Process32First            KERNEL32$Process32First
#define CloseHandle               KERNEL32$CloseHandle
#define Process32Next             KERNEL32$Process32Next

// Msvcrt
DECLSPEC_IMPORT int __cdecl MSVCRT$lstrcmpiA(LPCSTR ,LPCSTR);

#define lstrcmpiA    MSVCRT$lstrcmpiA

#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else

#define PRINT(...)  printf(__VA_ARGS__);

#endif
