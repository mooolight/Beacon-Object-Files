/*

 
 Credits: 
   - Heavily dependent on code by reenz0h (twitter: @SEKTOR7net) => Red Team Operator course code template Classic Process enumeration

*/
#include "procenum-classic-imports.h"

int FindTarget(const char *procname) {
	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
	
	// create a snapshot
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
			
	pe32.dwSize = sizeof(PROCESSENTRY32); 
	
	// and start to parse it from the first entry
	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		PRINT("Failed to get the next process in the linked list.\n");
		return -1;
	}
	
	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
				pid = pe32.th32ProcessID;
				PRINT("Found the target process.\n");
				break;
		}
	}
	CloseHandle(hProcSnap);
	return pid;
}

#ifdef BOF

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
	PRINT("Process:%s - %s%d)\n", procName ,pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);
	return;
}

#else

int main(){
	char* procName = "calculator.exe";
	/*
	// Prepare data parser
	datap parser;
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	procName = BeaconDataExtract(&parser, NULL);
	*/
	//int pid = FindTarget("notepad.exe");
	int pid = FindTarget(procName);
	PRINT("Process:%s - %s%d)\n", procName ,pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);
	return 0;
}

#endif
