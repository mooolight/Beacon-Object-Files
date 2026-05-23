/*

 
 Credits: 
   - Heavily dependent on code by reenz0h (twitter: @SEKTOR7net) => Red Team Operator course code template Classic Process enumeration

*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "..\beacon.h"
#include "..\bofdefs.h"
// 
// Kernel32
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD ,DWORD);  // Nt equivalent == 
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);  // Nt equivalent == 
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);  // Nt equivalent == 
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);  // Nt equivalent == 

// Msvcrt
DECLSPEC_IMPORT int __cdecl MSVCRT$lstrcmpiA(LPCSTR ,LPCSTR);


int FindTarget(const char *procname) {
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
	
	// create a snapshot
	hProcSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
			
	pe32.dwSize = sizeof(PROCESSENTRY32); 
	
	// and start to parse it from the first entry
	if (!KERNEL32$Process32First(hProcSnap, &pe32)) {
		KERNEL32$CloseHandle(hProcSnap);
		BeaconPrintf(CALLBACK_OUTPUT, "Failed to get the next process in the linked list.\n");
		return -1;
	}
	
	while (KERNEL32$Process32Next(hProcSnap, &pe32)) {
		if (MSVCRT$lstrcmpiA(procname, pe32.szExeFile) == 0) {
				pid = pe32.th32ProcessID;
				BeaconPrintf(CALLBACK_OUTPUT, "Found the target process.\n");
				break;
		}
	}
	KERNEL32$CloseHandle(hProcSnap);
	return pid;
}


// Usage: procenum-classic <procName>
void go(char *args, int alen) {
	char* procName;
	
	// Prepare data parser
	datap parser;
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	procName = BeaconDataExtract(&parser, NULL);
	
	//int pid = FindTarget("notepad.exe");
	int pid = FindTarget(procName);
	BeaconPrintf(CALLBACK_OUTPUT, "Process:%s - %s%d)\n", procName ,pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);
	return;
}