#pragma once

#ifdef BOF

extern "C" {
	#include "..\beacon.h"
	#include "..\bofdefs.h"

	// Kernel32
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$OpenProcessToken(HANDLE ,DWORD ,HANDLE*);
	#define OpenProcessToken KERNEL32$OpenProcessToken
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
	#define GetCurrentProcess KERNEL32$GetCurrentProcess
	DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
	#define GetLastError KERNEL32$GetLastError
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
	#define CloseHandle KERNEL32$CloseHandle
	
	
	// Advapi32
	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR ,LPCSTR, PLUID);
	#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
	#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);
	#define LookupPrivilegeNameA ADVAPI32$LookupPrivilegeNameA
	DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
	#define GetTokenInformation ADVAPI32$GetTokenInformation

	// Ole32
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID,DWORD);
	#define CoInitializeEx OLE32$CoInitializeEx
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR,LONG,SOLE_AUTHENTICATION_SERVICE*,void*,DWORD,DWORD,void*,DWORD,void*);
	#define CoInitializeSecurity OLE32$CoInitializeSecurity
	DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
	#define CoUninitialize OLE32$CoUninitialize
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
	#define CoCreateInstance OLE32$CoCreateInstance
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*,DWORD,DWORD,OLECHAR*,DWORD,DWORD,RPC_AUTH_IDENTITY_HANDLE,DWORD);
	#define CoSetProxyBlanket OLE32$CoSetProxyBlanket

	// OleAuth32
	WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR *);
	#define SysAllocString OLEAUT32$SysAllocString
	WINBASEAPI HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG *);
	#define VariantClear OLEAUT32$VariantClear
	WINBASEAPI void WINAPI OLEAUT32$SysFreeString(BSTR);
	#define SysFreeString OLEAUT32$SysFreeString

	// MSVCRT
	WINBASEAPI void* WINAPI MSVCRT$calloc(size_t ,size_t);
	#define calloc MSVCRT$calloc
	WINBASEAPI void __cdecl MSVCRT$free(void*);
	#define free MSVCRT$free
	

	#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)
}

#else

	#define PRINT(...)  printf(__VA_ARGS__);

#endif