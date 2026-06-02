#pragma once

#ifdef BOF

#include "..\beacon.h"
// Kernel32
DECLSPEC_IMPORT HANDLE 	WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD ,DWORD);
DECLSPEC_IMPORT BOOL   	WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   	WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL   	WINAPI KERNEL32$CloseHandle(HANDLE);
//DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
DECLSPEC_IMPORT LPVOID 	WINAPI KERNEL32$HeapReAlloc(HANDLE,DWORD,LPVOID,SIZE_T);
WINBASEAPI 		HANDLE 	WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT BOOL 	WINAPI KERNEL32$HeapDestroy(HANDLE hHeap);
DECLSPEC_IMPORT HANDLE 	WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName,
												  DWORD dwDesiredAccess,
												  DWORD dwShareMode,
												  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
												  DWORD dwCreationDisposition,
												  DWORD dwFlagsAndAttributes,
												  HANDLE hTemplateFile);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile,
											  LPVOID lpBuffer,
											  DWORD nNumberOfBytesToRead,
											  LPDWORD lpNumberOfBytesRead,
											  LPOVERLAPPED lpOverlapped);
WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);


#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot
#define Process32First           KERNEL32$Process32First
#define Process32Next            KERNEL32$Process32Next
#define CloseHandle              KERNEL32$CloseHandle
#define HeapFree                 KERNEL32$HeapFree
#define HeapReAlloc              KERNEL32$HeapReAlloc
#define GetProcessHeap           KERNEL32$GetProcessHeap
#define HeapDestroy              KERNEL32$HeapDestroy
#define CreateFileA              KERNEL32$CreateFileA
#define ReadFile                 KERNEL32$ReadFile
#define FindFirstFileA           KERNEL32$FindFirstFileA
#define FindNextFileA            KERNEL32$FindNextFileA
#define FindClose                KERNEL32$FindClose



// Advapi32 imports
WINBASEAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
WINBASEAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
WINBASEAPI BOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
WINBASEAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINBASEAPI BOOL WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName);


#define OpenSCManagerA        ADVAPI32$OpenSCManagerA
#define OpenServiceA          ADVAPI32$OpenServiceA
#define QueryServiceConfigA   ADVAPI32$QueryServiceConfigA
#define CloseServiceHandle    ADVAPI32$CloseServiceHandle
#define EnumServicesStatusExA ADVAPI32$EnumServicesStatusExA


// Msvcrt
WINBASEAPI INT	 __cdecl	MSVCRT$fopen(const char *, const char *);
WINBASEAPI CHAR* __cdecl 	MSVCRT$fgets(char *,int ,FILE *);
WINBASEAPI VOID* __cdecl 	MSVCRT$realloc(void *,size_t);
WINBASEAPI CHAR* __cdecl 	MSVCRT$strtok(char *,const char *);
WINBASEAPI CHAR* __cdecl 	MSVCRT$strcpy(char *,const char *);
WINBASEAPI INT	 __cdecl	   MSVCRT$fclose(FILE *);
WINBASEAPI INT   __cdecl   MSVCRT$_stricmp(const char *, const char *);
WINBASEAPI VOID* __cdecl 	MSVCRT$free(void*);
WINBASEAPI VOID* __cdecl 	MSVCRT$malloc(size_t);
WINBASEAPI char* __cdecl	MSVCRT$strncpy(char *, const char *, size_t);
WINBASEAPI void* __cdecl 	MSVCRT$memset(void *, int , size_t);
WINBASEAPI int 	 __cdecl 	MSVCRT$ferror(FILE *);
WINBASEAPI size_t __cdecl 	MSVCRT$fread(void *,size_t ,size_t ,FILE *);
WINBASEAPI size_t 	__cdecl MSVCRT$strlen(const char *);
WINBASEAPI int 		__cdecl MSVCRT$getchar();
WINBASEAPI char	 	__cdecl MSVCRT$strcat(char *strDestination,const char *strSource);
WINBASEAPI int	 	__cdecl MSVCRT$fflush(FILE *stream);
WINBASEAPI size_t	__cdecl MSVCRT$strcspn(const char *str, const char *strCharSet);
WINBASEAPI void* 	__cdecl MSVCRT$memcpy(void *dest,const void *src,size_t count);
WINBASEAPI char* 	__cdecl MSVCRT$strtok_s(char* str,const char* delimiters,char** context);
WINBASEAPI char* 	__cdecl MSVCRT$strstr(const char *haystack, const char *needle);
WINBASEAPI int 		__cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
WINBASEAPI int 		__cdecl MSVCRT$sprintf(char *__stream, const char *__format);
WINBASEAPI int 		__cdecl MSVCRT$memcmp(const void *buffer1,const void *buffer2,size_t count);
WINBASEAPI size_t 	__cdecl MSVCRT$wcstombs(char *mbstr,const wchar_t *wcstr,size_t count);


#define fopen     MSVCRT$fopen
#define fgets     MSVCRT$fgets
#define realloc   MSVCRT$realloc
#define strtok    MSVCRT$strtok
#define strcpy    MSVCRT$strcpy
#define fclose    MSVCRT$fclose
#define _stricmp  MSVCRT$_stricmp
#define free      MSVCRT$free
#define malloc    MSVCRT$malloc
#define strncpy   MSVCRT$strncpy
#define memset    MSVCRT$memset
#define ferror    MSVCRT$ferror
#define fread     MSVCRT$fread
#define strlen    MSVCRT$strlen
#define getchar   MSVCRT$getchar
#define strcat    MSVCRT$strcat
#define fflush    MSVCRT$fflush
#define strcspn   MSVCRT$strcspn
#define memcpy    MSVCRT$memcpy
#define strtok_s  MSVCRT$strtok_s
#define strstr    MSVCRT$strstr
#define strcmp    MSVCRT$strcmp
#define sprintf   MSVCRT$sprintf
#define memcmp    MSVCRT$memcmp
#define wcstombs  MSVCRT$wcstombs

#define PRINT(...)  BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__)

#else

#define PRINT(...)  printf(__VA_ARGS__);

#endif