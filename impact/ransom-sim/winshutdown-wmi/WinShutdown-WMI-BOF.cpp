/*
	Author : mooolight
	
	Pre-requisites: SeShutdownPrivilege - Shut down the system - Enabled
*/
#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <stdio.h>
#include <ole2.h>
#include "WinShutdown-WMI-BOF-imports.h"

#pragma comment(lib, "wbemuuid.lib")

// Verified and Working [/]
extern "C" void PrintTokenPrivileges(HANDLE hToken) {
	// 1. Query required buffer size
	DWORD dwSize = 0;
	GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize); // asks how much memory is needed
	
	// 2. Allocate and fill
	TOKEN_PRIVILEGES* pPriv = (TOKEN_PRIVILEGES*)calloc(1, dwSize);
	if(!GetTokenInformation(hToken, TokenPrivileges, pPriv, dwSize, &dwSize)) {
		PRINT("[!] GetTokenInformation failed: %lu\n", GetLastError());
		free(pPriv);
		return;
	}
	
	// 3. Iterate and print
	BOOL LPNState = FALSE;
	PRINT("[+] Token has %lu privileges:\n", pPriv->PrivilegeCount);
	for(DWORD i = 0; i < pPriv->PrivilegeCount; i++) {
		char name[256] = {0};
		DWORD nameLen = sizeof(name);
		if(!LookupPrivilegeNameA(NULL, &pPriv->Privileges[i].Luid, name, &nameLen)) {
			PRINT("[!] Failed to execute LookupPrivilegeNameA: %d\n",GetLastError());
			LPNState = TRUE;
			break;
		}
		
		const char* state = (pPriv->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled";
		
		PRINT(" %-40s [%s]  LUID=0x%08lX  Attr=0x%lX\n", name, 
														 state, 
														 pPriv->Privileges[i].Luid.LowPart,
														 pPriv->Privileges[i].Attributes);
	}

	free(pPriv);
	return;
}


extern "C" void PrintLUID(const LUID& luid, const char* name = "") {
	if(name[0])
		PRINT("%s: ", name);
	PRINT("0x%08lX%08lX\n", (unsigned long)luid.HighPart,
							(unsigned long)luid.LowPart);
	return;
}


extern "C" BOOL EnableShutdownPrivilege() {
	HANDLE hToken;
	if(!OpenProcessToken(GetCurrentProcess(),
						 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
						 &hToken)) {
		PRINT("[!] Failed to open the process' token: %d\n", GetLastError());
		return FALSE;
	}
	PRINT("[+] Handle to token extracted: 0x%08lX\n", hToken);
	
	LUID luid;
	if(!LookupPrivilegeValueA(NULL, "SeShutdownPrivilege", &luid)) {
		PRINT("[!] Failed to lookup the privilege value: %d\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}
	
	char* luidVal = "";
	PrintLUID(luid, luidVal);
	PRINT("[+] Successfully looked up the privilege value: SE_SHUTDOWN_NAME - %s", luidVal);
	
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if(!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) { 
		PRINT("[!] Failed to enable the SE_SHUTDOWN_NAME privilege: %d\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}
	
	PRINT("[+] ---------- Confirming that the SE_SHUTDOWN_NAME has been enabled ---------- \n\n");
	PrintTokenPrivileges(hToken);
	
	CloseHandle(hToken);
	return TRUE;
}

#ifdef BOF

// Usage: winshutdown-wmi-bof
extern "C" void go(char *args, int alen) {
	datap parser;
	
	// Prepare data parser
	BeaconDataParse(&parser, args, alen);

	GUID clsid = {0x4590f811, 0x1d3a, 0x11d0, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24};
	GUID iid   = {0xdc12a687, 0x737f, 0x11cf, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24};
	
	HRESULT hr;
	
	if(!EnableShutdownPrivilege()) {
		PRINT("[!] Failed to enable the SE_SHUTDOWN_NAME privilege. Exitting...\n");
		return;
	}
	PRINT("[+] Successfully enabled the SE_SHUTDOWN_NAME privilege!\n");
	
	// Initialize the COM
	hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if(FAILED(hr)) {
		PRINT("[*] CoInitializeEx failed: 0x%08lX\n", hr);
		return;
	}
	
	// Initialize the COM security
	hr = CoInitializeSecurity(nullptr, 
								-1, 
								nullptr, 
								nullptr, 
								RPC_C_AUTHN_LEVEL_DEFAULT,
								RPC_C_IMP_LEVEL_IMPERSONATE,
								nullptr,
								EOAC_NONE,
								nullptr);

	if(FAILED(hr)) {
		PRINT("[*] CoInitializeSecurity failed: 0x%08lX\n", hr);
		CoUninitialize();
		return;
	}
	

	IWbemLocator* pLocator = nullptr;
	IWbemServices* pServices = nullptr;
	
	// Create WMI locator
	hr = CoCreateInstance(clsid,
							nullptr,
							CLSCTX_INPROC_SERVER,   // No need to use CoSetProxyBlanket when this flag is set.
							iid,
							reinterpret_cast<void**>(&pLocator));
	
	if(FAILED(hr)) {
		PRINT("[*] CoCreateInstance failed: 0x%08lX\n", hr);
		CoUninitialize();
		return;
	}

	// Connect to WMI
	//BSTR server = (BSTR)OLESTR("WinMgmts:{impersonate,(Shutdown)}!\\\\.\\root\\cimv2");   // The (Shutdown) flag in the moniker is what grants the privilege - This introduces Scripting API
	// Reference 1: learn.microsoft.com/en-us/windows/win32/wmisdk/constructing-a-moniker-string
	// Reference 2: learn.microsoft.com/en-us/windows/win32/wmisdk/scripting-api-objects
	BSTR bstrServer = SysAllocString(L"ROOT\\CIMV2"); 
	hr = pLocator->ConnectServer(bstrServer,
								nullptr,
								nullptr,
								nullptr,
								0,
								nullptr,
								nullptr,
								&pServices);
	
	PRINT("[+] Successfully connected to path using ConnectServer().\n");
	SysFreeString(bstrServer);
	
	if(FAILED(hr)) {
		PRINT("[*] ConnectServer failed: 0x%08lX\n", hr);
		pLocator->Release();
		CoUninitialize();
		return;
	}
	
	// Set security level for the service
	hr = CoSetProxyBlanket(pServices,
							RPC_C_AUTHN_WINNT,
							RPC_C_AUTHZ_NONE,
							NULL,
							RPC_C_AUTHN_LEVEL_CALL,
							RPC_C_IMP_LEVEL_IMPERSONATE,
							NULL,
							EOAC_NONE);
	
	
	// Enumerate Win32_OperatingSystem instance and extract "bstrPath"
	IEnumWbemClassObject* pEnum = NULL;
	BSTR bstrQuery = SysAllocString(L"SELECT __PATH FROM Win32_OperatingSystem");
	BSTR bstrLang = SysAllocString(L"WQL");
	hr = pServices->ExecQuery(bstrLang, bstrQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
	SysFreeString(bstrQuery);
	SysFreeString(bstrQuery);
	if(FAILED(hr)) {
		PRINT("[!] ExecQuery: 0x%08X\n", hr);
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return;
	}
	
	IWbemClassObject* pInstance = NULL;
	ULONG uCount = 0;
	hr = pEnum->Next(WBEM_INFINITE, 1, &pInstance, &uCount);
	pEnum->Release();
	if(FAILED(hr) || !pInstance) {
		PRINT("Next: 0x%08X\n", hr);
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return;
	}
	
	// Extract instance __PATH
	VARIANT val;
	VariantInit(&val);
	BSTR bstrProp = SysAllocString(L"__PATH");
	hr = pInstance->Get(bstrProp, 0, &val, NULL, NULL);
	SysFreeString(bstrProp);
	if(FAILED(hr) || val.vt != VT_BSTR) {
		PRINT("[!] Get __PATH: 0x%08X\n", hr);
		VariantClear(&val);
		pInstance->Release();
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return;
	}
	BSTR bstrPath = val.bstrVal; // heap BSTR owned by WMI


	// Get the CLASS object (not instance) for method definition
	IWbemClassObject* pClass = NULL;
	hr = pServices->GetObject(L"Win32_OperatingSystem",
								0, NULL, &pClass, NULL);
	
	if(FAILED(hr)) {
		PRINT("[!] Extracting Win32Shutdown() method failed: 0x%08X\n", hr);
		VariantClear(&val);
		pInstance->Release();
		pClass->Release();
		pServices->Release();
		pLocator->Release();
	}
	
	
	// ============= Call Win32_OperatingSystem.Shutdown() =============
	// Get the Win32Shutdown method
	IWbemClassObject* pInParams = NULL;  // stores the address for the method prior to execution
	hr = pClass->GetMethod(L"Win32Shutdown", 0, &pInParams, NULL);
	
	if(FAILED(hr)) {
		PRINT("[!] Extracting Win32Shutdown() method failed: 0x%08X\n", hr);
		pInstance->Release();
		pClass->Release();
		pServices->Release();
		pLocator->Release();
		return;
	}
	
	PRINT("[+] Successfully extracted Win32Shutdown() method!\n");
	
	// Spawn in-params instance
	IWbemClassObject* pClassInstance = NULL;   // holds the instance object for Win32Shutdown() method. 
	hr = pInParams->SpawnInstance(0, &pClassInstance);
	if(FAILED(hr)) {
		PRINT("Extraction of method instance for Win32Shutdown() failed: 0x%08X\n", hr);
		pInstance->Release();
		pInParams->Release();
		pClass->Release();
		pLocator->Release();
		pServices->Release();
		CoUninitialize();
		return;
	}
	
	// Set Flags: 
	// 8 = Power Off, 
	// 1 = Shutdown - but this doesnt power off the computer
	// 2 = Reboot, 0 = Log Off
	// Add 4 to force Log OFf (e.g., 12 = Forced Power Off)
	VARIANT varFlags;
	VariantInit(&varFlags);
	varFlags.vt = VT_I4;
	varFlags.lVal = 1; // Power Off flag
	hr = pClassInstance->Put(L"Flags", 0, &varFlags, 0);
	
	// Set the Reserved to 0
	VARIANT vtReserved;
	VariantInit(&vtReserved);
	vtReserved.vt = VT_UI2;
	vtReserved.uintVal = 0;
	hr = pClassInstance->Put(L"Reserved", 0, &vtReserved, 0);
	
	PRINT("[+] Successfully set the flags needed.\n");
	
	
	// Call Win32Shutdown
	// Other functions: Reboot, Win32Shutdown(), Win32ShutdownTracker()
	IWbemClassObject* pOutParams = NULL;
	hr = pServices->ExecMethod(bstrPath, 
								L"Win32Shutdown", 
								0, 
								NULL, 
								pClassInstance, 
								&pOutParams, 
								NULL);
	
	if(FAILED(hr)) {
		PRINT("[!] Win32Shutdown failed: 0x%08X\n", hr);
		pInstance->Release();
		pInParams->Release();
		pClass->Release();
		pLocator->Release();
		pServices->Release();
		CoUninitialize();
		return;
	}
	
	
	VARIANT varResult;
	VariantInit(&varResult);
	pOutParams->Get(L"ReturnValue", 
					0,
					&varResult, NULL, NULL);
	
	PRINT("Return value: %d\n", varResult.lVal);
	VariantClear(&varResult);
	pOutParams->Release();
	
	// Cleanup
	//pObject->Release();
	pInstance->Release();
	pEnum->Release();
	pInParams->Release();
	pClassInstance->Release();
	VariantClear(&val);
	pServices->Release();
	pLocator->Release();
	CoUninitialize();
	return;
}

#else

int main() {
	GUID clsid = {0x4590f811, 0x1d3a, 0x11d0, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24};
	GUID iid   = {0xdc12a687, 0x737f, 0x11cf, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24};
	
	HRESULT hr;

	if(!EnableShutdownPrivilege()) {
		PRINT("[!] Failed to enable the SE_SHUTDOWN_NAME privilege. Exitting...\n");
		return;
	}
	PRINT("[+] Successfully enabled the SE_SHUTDOWN_NAME privilege!\n");

	
	// Initialize the COM
	hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if(FAILED(hr)) {
		PRINT("[*] CoInitializeEx failed: 0x%08lX\n", hr);
		return 0;
	}
	
	// Initialize the COM security
	hr = CoInitializeSecurity(nullptr, 
								-1, 
								nullptr, 
								nullptr, 
								RPC_C_AUTHN_LEVEL_DEFAULT,
								RPC_C_IMP_LEVEL_IMPERSONATE,
								nullptr,
								EOAC_NONE,
								nullptr);

	if(FAILED(hr)) {
		PRINT("[*] CoInitializeSecurity failed: 0x%08lX\n", hr);
		CoUninitialize();
		return 0;
	}
	

	IWbemLocator* pLocator = nullptr;
	IWbemServices* pServices = nullptr;
	
	// Create WMI locator
	hr = CoCreateInstance(clsid,
							nullptr,
							CLSCTX_INPROC_SERVER,   // No need to use CoSetProxyBlanket when this flag is set.
							iid,
							reinterpret_cast<void**>(&pLocator));
	
	if(FAILED(hr)) {
		PRINT("[*] CoCreateInstance failed: 0x%08lX\n", hr);
		CoUninitialize();
		return 0;
	}

	// Connect to WMI
	BSTR bstrServer = SysAllocString(L"ROOT\\CIMV2");
	hr = pLocator->ConnectServer(bstrServer,
								nullptr,
								nullptr,
								nullptr,
								0,
								nullptr,
								nullptr,
								&pServices);
	
	PRINT("[+] Successfully connected to path using ConnectServer().\n");
	SysFreeString(bstrServer);
	
	if(FAILED(hr)) {
		PRINT("[*] ConnectServer failed: 0x%08lX\n", hr);
		pLocator->Release();
		CoUninitialize();
		return 0;
	}
	
	// Set security level for the service
	hr = CoSetProxyBlanket(pServices,
							RPC_C_AUTHN_WINNT,
							RPC_C_AUTHZ_NONE,
							NULL,
							RPC_C_AUTHN_LEVEL_CALL,
							RPC_C_IMP_LEVEL_IMPERSONATE,
							NULL,
							EOAC_NONE);
	
	
	// Enumerate Win32_OperatingSystem instance and extract "bstrPath"
	IEnumWbemClassObject* pEnum = NULL;
	BSTR bstrQuery = SysAllocString(L"SELECT __PATH FROM Win32_OperatingSystem");
	BSTR bstrLang = SysAllocString(L"WQL");
	hr = pServices->ExecQuery(bstrLang, bstrQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnum);
	SysFreeString(bstrQuery);
	SysFreeString(bstrQuery);
	if(FAILED(hr)) {
		PRINT("[!] ExecQuery: 0x%08X\n", hr);
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return 0;
	}
	
	IWbemClassObject* pInstance = NULL;
	ULONG uCount = 0;
	hr = pEnum->Next(WBEM_INFINITE, 1, &pInstance, &uCount);
	pEnum->Release();
	if(FAILED(hr) || !pInstance) {
		PRINT("Next: 0x%08X\n", hr);
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return 0;
	}
	
	// Extract instance __PATH
	VARIANT val;
	VariantInit(&val);
	BSTR bstrProp = SysAllocString(L"__PATH");
	hr = pInstance->Get(bstrProp, 0, &val, NULL, NULL);
	SysFreeString(bstrProp);
	if(FAILED(hr) || val.vt != VT_BSTR) {
		PRINT("[!] Get __PATH: 0x%08X\n", hr);
		VariantClear(&val);
		pInstance->Release();
		pServices->Release();
		pLocator->Release();
		CoUninitialize();
		return 0;
	}
	BSTR bstrPath = val.bstrVal; // heap BSTR owned by WMI


	// Get the CLASS object (not instance) for method definition
	IWbemClassObject* pClass = NULL;
	hr = pServices->GetObject(L"Win32_OperatingSystem",
								0, NULL, &pClass, NULL);
	
	if(FAILED(hr)) {
		PRINT("[!] Extracting Win32Shutdown() method failed: 0x%08X\n", hr);
		VariantClear(&val);
		pInstance->Release();
		pClass->Release();
		pServices->Release();
		pLocator->Release();
	}
	
	
	// ============= Call Win32_OperatingSystem.Shutdown() =============
	// Get the Win32Shutdown method
	IWbemClassObject* pInParams = NULL;  // stores the address for the method prior to execution
	hr = pClass->GetMethod(L"Win32Shutdown", 0, &pInParams, NULL);
	
	if(FAILED(hr)) {
		PRINT("[!] Extracting Win32Shutdown() method failed: 0x%08X\n", hr);
		pInstance->Release();
		pClass->Release();
		pServices->Release();
		pLocator->Release();
		return 0;
	}
	PRINT("[+] Successfully extracted Win32Shutdown() method!\n");
	
	// Spawn in-params instance
	IWbemClassObject* pClassInstance = NULL;   // holds the instance object for Win32Shutdown() method. 
	hr = pInParams->SpawnInstance(0, &pClassInstance);
	if(FAILED(hr)) {
		PRINT("Extraction of method instance for Win32Shutdown() failed: 0x%08X\n", hr);
		pInstance->Release();
		pInParams->Release();
		pClass->Release();
		pLocator->Release();
		pServices->Release();
		CoUninitialize();
		return 0;
	}
	
	
	// Set Flags: 
	// 8 = Power Off, 
	// 1 = Shutdown - but this doesnt power off the computer
	// 2 = Reboot, 0 = Log Off
	// Add 4 to force Log OFf (e.g., 12 = Forced Power Off)
	VARIANT varFlags;
	VariantInit(&varFlags);
	varFlags.vt = VT_I4;
	varFlags.lVal = 1; // Power Off flag
	hr = pClassInstance->Put(L"Flags", 0, &varFlags, 0);
	
	// Set the Reserved to 0
	VARIANT vtReserved;
	VariantInit(&vtReserved);
	vtReserved.vt = VT_UI2;
	vtReserved.uintVal = 0;
	hr = pClassInstance->Put(L"Reserved", 0, &vtReserved, 0);
	
	// Call Win32Shutdown
	// Other functions: Reboot, Win32Shutdown(), Win32ShutdownTracker()
	IWbemClassObject* pOutParams = NULL;
	hr = pServices->ExecMethod(bstrPath, 
								L"Win32Shutdown", 
								0, 
								NULL, 
								pClassInstance, 
								&pOutParams, 
								NULL);
	
	if(FAILED(hr)) {
		PRINT("[!] Win32Shutdown failed: 0x%08X\n", hr);
		pInstance->Release();
		pInParams->Release();
		pClass->Release();
		pLocator->Release();
		pServices->Release();
		CoUninitialize();
		return 0;
	}
	
	
	VARIANT varResult;
	VariantInit(&varResult);
	pOutParams->Get(L"ReturnValue", 
					0,
					&varResult, NULL, NULL);
	
	PRINT("Return value: %d\n", varResult.lVal);
	VariantClear(&varResult);
	pOutParams->Release();
	
	// Cleanup
	//pObject->Release();
	pInstance->Release();
	pEnum->Release();
	pInParams->Release();
	pClassInstance->Release();
	VariantClear(&val);
	pServices->Release();
	pLocator->Release();
	CoUninitialize();
	return 0;
}

#endif
