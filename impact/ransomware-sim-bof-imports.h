#pragma once

#ifdef BOF
	// Kernel32
	DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(LPCSTR ,DWORD ,DWORD ,LPSECURITY_ATTRIBUTES ,DWORD ,DWORD , HANDLE);
	#define CreateFileA KERNEL32$CreateFileA
	DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$CloseHandle(HANDLE);
	#define CloseHandle KERNEL32$CloseHandle
	DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$GetFileSizeEx(HANDLE,PLARGE_INTEGER);
	#define GetFileSizeEx KERNEL32$GetFileSizeEx
	DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
	#define GetFileSize KERNEL32$GetFileSize
	DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile(HANDLE ,LPCVOID ,DWORD ,LPDWORD ,LPOVERLAPPED);
	#define WriteFile KERNEL32$WriteFile
	DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$ReadFile(HANDLE ,LPVOID ,DWORD  ,LPDWORD ,LPOVERLAPPED);
	#define ReadFile KERNEL32$ReadFile
	
	// Advapi32
	WINADVAPI BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
	#define CryptDestroyKey ADVAPI32$CryptDestroyKey
	WINADVAPI BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV *,LPCSTR ,LPCSTR ,DWORD ,DWORD);
	#define CryptAcquireContextA ADVAPI32$CryptAcquireContextA
	WINADVAPI BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV ,DWORD);
	#define CryptReleaseContext ADVAPI32$CryptReleaseContext
	WINADVAPI BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV ,ALG_ID ,HCRYPTKEY ,DWORD ,HCRYPTHASH *);
	#define CryptCreateHash ADVAPI32$CryptCreateHash
	WINADVAPI BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH ,const BYTE *,DWORD ,DWORD);
	#define CryptHashData ADVAPI32$CryptHashData
	WINADVAPI BOOL WINAPI ADVAPI32$CryptDeriveKey(HCRYPTPROV ,ALG_ID ,HCRYPTHASH ,DWORD ,HCRYPTKEY*);
	#define CryptDeriveKey ADVAPI32$CryptDeriveKey
	WINADVAPI BOOL WINAPI ADVAPI32$CryptEncrypt(HCRYPTKEY ,HCRYPTHASH ,BOOL ,DWORD ,BYTE* ,DWORD* ,DWORD);
	#define CryptEncrypt ADVAPI32$CryptEncrypt
	WINADVAPI BOOL WINAPI ADVAPI32$CryptDecrypt(HCRYPTKEY ,HCRYPTHASH ,BOOL ,DWORD ,BYTE* ,DWORD*);
	#define CryptDecrypt ADVAPI32$CryptDecrypt
	
	// Msvcrt
	WINBASEAPI void* __cdecl MSVCRT$memset(void *,int,size_t);
	#define memset MSVCRT$memset
	WINBASEAPI void* __cdecl MSVCRT$free(void*);
	#define free MSVCRT$free
	WINBASEAPI void* __cdecl MSVCRT$malloc(size_t);
	#define malloc MSVCRT$malloc
	WINBASEAPI char * __cdecl MSVCRT$strcpy(char *,const char *);
	#define strcpy MSVCRT$strcpy
	WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *);
	#define strlen MSVCRT$strlen
#endif