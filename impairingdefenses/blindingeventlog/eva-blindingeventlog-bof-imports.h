#pragma once

#ifdef BOF
// Kernel32 - DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	DECLSPEC_IMPORT BOOL KERNEL32$OpenProcessToken(HANDLE,DWORD,PHANDLE);
	#define OpenProcessToken KERNEL32$OpenProcessToken
	DECLSPEC_IMPORT HANDLE KERNEL32$OpenProcess(DWORD,BOOL,DWORD);
	#define OpenProcess KERNEL32$OpenProcess
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD ,DWORD);
	#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Thread32First(HANDLE,LPTHREADENTRY32);
	#define Thread32First KERNEL32$Thread32First
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
	#define CloseHandle KERNEL32$CloseHandle
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread(DWORD,BOOL,DWORD);
	#define OpenThread KERNEL32$OpenThread
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$IsWow64Process(HANDLE,PBOOL);
	#define IsWow64Process KERNEL32$IsWow64Process
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
	#define ReadProcessMemory KERNEL32$ReadProcessMemory
	DECLSPEC_IMPORT DWORD WINAPI KERNEL32$SuspendThread(HANDLE hThread);
	#define SuspendThread KERNEL32$SuspendThread
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Thread32Next(HANDLE,LPTHREADENTRY32);
	#define Thread32Next KERNEL32$Thread32Next
	DECLSPEC_IMPORT BOOL WINAPI KERNEL32$TerminateThread(HANDLE,DWORD);
	#define TerminateThread KERNEL32$TerminateThread
	WINBASEAPI 		DWORD 	WINAPI KERNEL32$GetLastError(VOID);
	#define GetLastError KERNEL32$GetLastError
	DECLSPEC_IMPORT DWORD 	WINAPI KERNEL32$GetCurrentProcessId();
	#define GetCurrentProcessId KERNEL32$GetCurrentProcessId
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
	#define GetCurrentProcess KERNEL32$GetCurrentProcess


	// Advapi32
	WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR ,LPCSTR ,PLUID);
	#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
	WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
	#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
	WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR,LPCSTR,DWORD);
	#define OpenSCManagerA ADVAPI32$OpenSCManagerA
	WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE,LPCSTR,DWORD);
	#define OpenServiceA ADVAPI32$OpenServiceA
	WINADVAPI BOOL WINAPI ADVAPI32$QueryServiceStatusEx(SC_HANDLE hService,SC_STATUS_TYPE InfoLevel,LPBYTE lpBuffer,DWORD cbBufSize,LPDWORD pcbBytesNeeded);
	#define QueryServiceStatusEx ADVAPI32$QueryServiceStatusEx


	// Msvcrt
	WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t*,const wchar_t*);
	#define _wcsicmp MSVCRT$_wcsicmp
#endif

