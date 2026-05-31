#pragma once

#define ENABLE 1
#define DISABLE 0

typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
	ServiceNameFromTagInformation = 1,
	ServiceNameReferencingModuleInformation,
	ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY {
	ULONG   processId;
	ULONG   serviceTag;
	ULONG   reserved;
	PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

typedef struct _CLIENT_ID {
	DWORD       uniqueProcess;
	DWORD       uniqueThread;

} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS    exitStatus;
	PVOID       pTebBaseAddress;
	CLIENT_ID   clientId;
	KAFFINITY   AffinityMask;
	int			Priority;
	int			BasePriority;
	int			v;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef ULONG (WINAPI * I_QueryTagInformation_t)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
typedef NTSTATUS (WINAPI * NtQueryInformationThread_t)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);



