#pragma once

#ifdef BOF
	#include "..\beacon.h"

	// Kernel32
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD ,DWORD);
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD,BOOL,DWORD);
	DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
	DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE ,LPVOID ,SIZE_T ,DWORD ,DWORD);
	DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteProcessMemory(HANDLE , LPVOID , LPCVOID , SIZE_T ,  SIZE_T  *);
	DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE ,DWORD);
	DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);
	DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
	DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
	DECLSPEC_IMPORT int	   WINAPI KERNEL32$lstrcmpiA(LPCSTR ,LPCSTR);

	#define CreateToolhelp32Snapshot		KERNEL32$CreateToolhelp32Snapshot
	#define OpenProcess						KERNEL32$OpenProcess
	#define CloseHandle						KERNEL32$CloseHandle
	#define VirtualAllocEx					KERNEL32$VirtualAllocEx
	#define WriteProcessMemory				KERNEL32$WriteProcessMemory
	#define WaitForSingleObject				KERNEL32$WaitForSingleObject
	#define CreateRemoteThread				KERNEL32$CreateRemoteThread
	#define Process32First					KERNEL32$Process32First
	#define Process32Next					KERNEL32$Process32Next
	#define lstrcmpiA						KERNEL32$lstrcmpiA

	// Advapi32
	WINADVAPI BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV *,LPCSTR ,LPCSTR ,DWORD ,DWORD);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV ,DWORD);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV ,ALG_ID ,HCRYPTKEY ,DWORD ,HCRYPTHASH *);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH ,const BYTE *,DWORD ,DWORD);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptDeriveKey(HCRYPTPROV ,ALG_ID ,HCRYPTHASH ,DWORD ,HCRYPTKEY*);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptEncrypt(HCRYPTKEY ,HCRYPTHASH ,BOOL ,DWORD ,BYTE* ,DWORD* ,DWORD);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptDecrypt(HCRYPTKEY ,HCRYPTHASH ,BOOL ,DWORD ,BYTE* ,DWORD*);
	WINADVAPI BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH hHash);

	#define CryptDestroyKey			ADVAPI32$CryptDestroyKey
	#define CryptAcquireContextA	ADVAPI32$CryptAcquireContextA
	#define CryptReleaseContext		ADVAPI32$CryptReleaseContext
	#define CryptCreateHash			ADVAPI32$CryptCreateHash
	#define CryptHashData			ADVAPI32$CryptHashData
	#define CryptDeriveKey			ADVAPI32$CryptDeriveKey
	#define CryptEncrypt			ADVAPI32$CryptEncrypt
	#define CryptDecrypt			ADVAPI32$CryptDecrypt
	#define CryptDestroyHash		ADVAPI32$CryptDestroyHash

	// Msvcrt
	DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void *,const void *,size_t);

	#define memcpy					MSVCRT$memcpy

	#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else
	
	#define PRINT(...)  printf(__VA_ARGS__);

#endif

