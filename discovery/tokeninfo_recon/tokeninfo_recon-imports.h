#pragma once

#ifdef BOF

#include "..\beacon.h"
#include "..\bofdefs.h"

// Kernel32.lib
//DECLSPEC_IMPORT <return_type> WINAPI <LIB>$<FUNCNAME>(param1, param2, ...);
DECLSPEC_IMPORT DWORD 	WINAPI KERNEL32$GetCurrentProcessId();
DECLSPEC_IMPORT VOID 	WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT HANDLE 	WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$OpenProcessToken(HANDLE ,DWORD ,PHANDLE);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL hMem);
DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
WINBASEAPI 		DWORD 	WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI 		HANDLE 	WINAPI KERNEL32$GetProcessHeap();

#define GetCurrentProcessId     KERNEL32$GetCurrentProcessId
#define Sleep                   KERNEL32$Sleep
#define Process32First          KERNEL32$Process32First
#define Process32Next           KERNEL32$Process32Next
#define OpenProcess             KERNEL32$OpenProcess
#define OpenProcessToken        KERNEL32$OpenProcessToken
#define GlobalAlloc             KERNEL32$GlobalAlloc
#define GlobalFree              KERNEL32$GlobalFree
#define CloseHandle             KERNEL32$CloseHandle
#define HeapAlloc               KERNEL32$HeapAlloc
#define LocalFree               KERNEL32$LocalFree
#define GetLastError            KERNEL32$GetLastError
#define GetProcessHeap          KERNEL32$GetProcessHeap


// Advapi32.lib
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD ,PDWORD);
WINADVAPI BOOL WINBASEAPI ADVAPI32$LookupAccountNameA(LPCSTR,LPCSTR,PSID,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE);
WINADVAPI BOOL WINBASEAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR *);
WINADVAPI BOOL WINAPI ADVAPI32$IsValidSid(PSID);
WINADVAPI BOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR ,PSID ,LPSTR ,LPDWORD ,LPSTR ,LPDWORD ,PSID_NAME_USE);
WINADVAPI BOOL WINAPI ADVAPI32$IsValidAcl(PACL);
WINADVAPI BOOL WINAPI ADVAPI32$GetAclInformation(PACL,LPVOID,DWORD,ACL_INFORMATION_CLASS);
WINADVAPI BOOL WINAPI ADVAPI32$GetAce(PACL,DWORD,LPVOID*);

#define GetTokenInformation     ADVAPI32$GetTokenInformation
#define LookupAccountNameA      ADVAPI32$LookupAccountNameA
#define ConvertSidToStringSidA  ADVAPI32$ConvertSidToStringSidA
#define IsValidSid              ADVAPI32$IsValidSid
#define LookupAccountSidA       ADVAPI32$LookupAccountSidA
#define IsValidAcl              ADVAPI32$IsValidAcl
#define GetAclInformation       ADVAPI32$GetAclInformation
#define GetAce                  ADVAPI32$GetAce


// Msvcrt
DECLSPEC_IMPORT int		__cdecl	MSVCRT$getchar();
DECLSPEC_IMPORT void* 	__cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT size_t 	__cdecl MSVCRT$strlen(const char *);
DECLSPEC_IMPORT void* 	__cdecl MSVCRT$free(void*);

#define getchar     MSVCRT$getchar
#define malloc      MSVCRT$malloc
#define strlen      MSVCRT$strlen
#define free        MSVCRT$free

#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else

#define PRINT(...)  printf(__VA_ARGS__);

#endif