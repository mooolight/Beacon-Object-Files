#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <malloc.h>
#include <objidlbase.h>
#include <winternl.h>
#include "..\beacon.h"
#include "..\bofdefs.h"
#include <string.h>
#include <psapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

/* Useful structure reference: This contains the metadata for the file/directory that I am currently hunting for.
typedef struct _WIN32_FIND_DATAA {
  DWORD    dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
  DWORD    dwReserved0;
  DWORD    dwReserved1;
  CHAR     cFileName[MAX_PATH];
  CHAR     cAlternateFileName[14];
  DWORD    dwFileType;
  DWORD    dwCreatorType;
  WORD     wFinderFlags;
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

*/

#define MAX_EDR_STRINGS 202
#define MAX_EDR_STRING_LENGTH 50
#define MAX_PATH_LENGTH MAX_PATH

#define CRYPT_STRING_BASE64 			0x00000001
#define CRYPT_STRING_NOCRLF 			0x40000000

// ========================= WinAPI hashes ======================
#define OPENSCMANAGERA			0x7A741E60
#define ENUMSERVICESSTATUSEXA 	0x11BB18DD
#define CLOSESERVICEHANDLE 	 	0x4010E9A5
#define OPENSERVICEA 		 	0x588AB52A
#define QUERYSERVICECONFIGA  	0x127FBF78
#define CRYPTBINARYTOSTRINGA	0xCE17A5EC

// Bcrypt
#define BCRYPTOPENALGORITHMPROVIDER  0x4A63EBA6
#define BCRYPTDERIVEKEYPBKDF2		 0xAE373DAD
#define BCRYPTDESTROYKEY			 0x613355BB
#define BCRYPTCLOSEALGORITHMPROVIDER 0xE357D4BA
#define BCRYPTSETPROPERTY 			 0x89B85307
#define BCRYPTGENERATESYMMETRICKEY 	 0xFB48726F
#define BCRYPTDECRYPT				 0x4158EE4F
#define BCRYPTGENRANDOM				 0xEC8BFB17


// Libraries
#define NTDLL                        0xfb4e1a2c  // ntdll.dll
#define KERNEL32                     0x0ad9a9a6  // kernel32.dll
#define ADVAPI32					 0xE8AB8048  // advapi32.dll
#define OLEAUT32 					 0xEE42A2EF
#define WININET                      0x35847a6e  // wininet.dll
#define DNSAPI						 0x5B5922CB	 // windns.h
#define WS2_32						 0x0D25D9EE  // Ws2_32.dll
#define SLEEP                        0xb60c818f  // sleep
#define AMSI 						 0xA9753030	 // amsi.dll
#define MSCOREE						 0x36022E24	 // mscoree.dll
#define CLR 						 0x1BAB2B79
#define BCRYPT						 0xC71E6F38
#define KERNELBASE 					 0xD8A74686

// ========================= EDR List ========================================
/*
#define activeconsole -> 0xB3FD5047
#define ADA-PreCheck -> 0x10BE3B80
#define ahnlab -> 0xCEC62B78
#define amsi.dll -> 0xA9753030
#define anti malware -> 0xFCDF2DFB
#define anti-malware -> 0x3364E832
#define antimalware -> 0x2E607513
#define "anti virus" -> 0xC35A3871
#define anti-virus -> 0x56AB9154
#define antivirus -> 0x90DDC059
#define appsense -> 0x95C8AD2B
#define "attivo networks" -> 0x99743B08
#define attivonetworks -> 0x6956E076
#define authtap -> 0x532D0FA3
#define avast -> 0x82AE14D1
#define avecto -> 0x37C7C4DE
#define bitdefender -> 0x221FBFA0
#define blackberry -> 0xE42B3419
#define canary -> 0x0AE93D3C
#define carbonblack -> 0x0A1CF1E8
#define "carbon black" -> 0x89A74222
#define cb.exe -> 0xD1141413
#define "check point" -> 0xDEFA8DE2
#define ciscoamp -> 0x2726309F
#define "cisco amp" -> 0x6D47D031
#define countercept -> 0xD7BA9168
#define countertack -> 0x372A2FD5
#define cramtray -> 0xEB5E8677
#define crssvc -> 0xD41FA2BC
#define crowdstrike -> 0x9C49FEFF
#define csagent 			 0x3054A96F
#define csfalcon 			 0x51F33DA7
#define csshell 			 0xBFAAD84C
#define cybereason 			 0x9B7E5031
#define cyclorama 			 0xA5FF8C77
#define cylance 			 0x5CF079CB
#define cynet 				 0x58B40427
#define cyoptics 			 0x53C4431A
#define cyupdate 			 0x4A3B003D
#define cyvera 				 0xE21F36F8
#define cyserver 			 0x8600086F
#define cytray 				 0x4488374C
#define darktrace 			 0x6D4FEF89
#define "deep instinct" 	 0x5F36EFF6
#define defendpoint 		 0xCD7EDAE6
#define defender 			 0xB67A5FD7
#define eectrl 				 0x57445D43
#define elastic 			 0xAA505F5F
#define endgame 			 0xC83C713B
#define f-secure 			 0x838C96FC
#define forcepoint 			 0x30663827
#define fortinet 			 0x9EB55D2F
#define fireeye 			 0x460D9F75
#define groundling 			 0xFC15FCC7
#define GRRservic 			 0x08EC76F5
#define harfanglab 			 0x6333E7A4
#define inspector 			 0xF72C02CD
#define ivanti 				 0x32CAF50F
#define "juniper networks"   0x764B1EFA
#define kaspersky 			 0xAF2AD9F1
#define lacuna 				 0x6E8EBA96
#define logrhythm 			 0x6786246A
#define malware 			 0x3B929DF3
#define malwarebytes 		 0xBA69C2A6
#define mandiant 			 0x947D93D0
#define mcafee 				 0x7DDCAE11
#define morphisec 			 0xFE9EC656
#define msascuil 			 0x7106E371
#define msmpeng 			 0x2199DD77
#define WinDefend			 0x1CCED17E
#define mssense 			 0x2AE007A6
#define nissrv 				 0x3647CD87
#define WdNisSvc			 0x90057D07
#define omni 				 0x1A10642D
#define omniagent 			 0x25A03C3E
#define osquery 			 0x52A20062
#define "Palo Alto Networks" 0xE32142D9
#define pgeposervice 		 0xDC963EF8
#define pgsystemtray 		 0x2E3D2230
#define privilegeguard 		 0x246B7B6C
#define procwall 			 0xDB9D21B8
#define protectorservic 	 0xD99C2996
#define qianxin 			 0xAE9AE6B4
#define qradar 				 0xC08DF999
#define qualys 				 0x5F79C5AF
#define rapid7 				 0x6C0DE72B
#define redcloak 			 0xDF4C8F49
#define "red canary" 		 0x7484565D
#define SanerNow 			 0x6B33A43B
#define sangfor 			 0xF9DE29CE
#define secureworks 		 0x652B9591
#define securityhealthservice 0x5EA92173
#define semlaunchsv 		 0x1DFA51AD
#define sentinel 			 0xC367BC2C
#define sentinelone 		 0x7A83BFF0
#define sepliveupdat 		 0x58FF8564
#define sisidsservice 		 0x5AD80150
#define sisipsservice 		 0x72ED6534
#define sisipsutil 			 0x448778D9
#define smc.exe 			 0x1AFCB807
#define smcgui 				 0xB25C5F4C
#define snac64 				 0x7C9707D3
#define somma 				 0x82BCDF9F
#define sophos 				 0x6A8460D0
#define splunk 				 0x15CECA17
#define srtsp 				 0x26C648E8
#define symantec 			 0x44C73180
#define symcorpu 			 0x958B0BD6
#define symefasi 			 0x79EFC8AF
#define sysinternal 		 0x622D0048
#define sysmon 				 0x12553259
#define tanium 				 0xCD8B5458
#define tda.exe 			 0xE6BF78B1
#define tdawork 			 0x32D102BA
#define tehtris 			 0xF2560E7F
#define threat 				 0x54026AB4
#define trellix 			 0x3F96D8A0
#define tpython 			 0xAAA8C8B2
#define "trend micro" 		 0x058D3FEF
#define uptycs 				 0x339CEDB0
#define vectra 				 0xA18664A7
#define watchguard 			 0xE6E11F2C
#define wincollect 			 0x3556E414
#define windowssensor 		 0x2AE5E7C7
#define wireshark 			 0x2B578A26
#define withsecure 			 0x27D87DB5
#define xagt.exe 			 0xA681F182
#define xagtnotif.exe		 0x0F2695D0
*/


typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
   struct _PEB_FREE_BLOCK * pNext;
   DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB // 65 elements, 0x210 bytes
{
   BYTE bInheritedAddressSpace;
   BYTE bReadImageFileExecOptions;
   BYTE bBeingDebugged;
   BYTE bSpareBool;
   LPVOID lpMutant;
   LPVOID lpImageBaseAddress;
   PPEB_LDR_DATA pLdr;
   LPVOID lpProcessParameters;
   LPVOID lpSubSystemData;
   LPVOID lpProcessHeap;
   PRTL_CRITICAL_SECTION pFastPebLock;
   LPVOID lpFastPebLockRoutine;
   LPVOID lpFastPebUnlockRoutine;
   DWORD dwEnvironmentUpdateCount;
   LPVOID lpKernelCallbackTable;
   DWORD dwSystemReserved;
   DWORD dwAtlThunkSListPtr32;
   PEB_FREE_BLOCK* pFreeList;
   DWORD dwTlsExpansionCounter;
   LPVOID lpTlsBitmap;
   DWORD dwTlsBitmapBits[2];
   LPVOID lpReadOnlySharedMemoryBase;
   LPVOID lpReadOnlySharedMemoryHeap;
   LPVOID lpReadOnlyStaticServerData;
   LPVOID lpAnsiCodePageData;
   LPVOID lpOemCodePageData;
   LPVOID lpUnicodeCaseTableData;
   DWORD dwNumberOfProcessors;
   DWORD dwNtGlobalFlag;
   LARGE_INTEGER liCriticalSectionTimeout;
   DWORD dwHeapSegmentReserve;
   DWORD dwHeapSegmentCommit;
   DWORD dwHeapDeCommitTotalFreeThreshold;
   DWORD dwHeapDeCommitFreeBlockThreshold;
   DWORD dwNumberOfHeaps;
   DWORD dwMaximumNumberOfHeaps;
   LPVOID lpProcessHeaps;
   LPVOID lpGdiSharedHandleTable;
   LPVOID lpProcessStarterHelper;
   DWORD dwGdiDCAttributeList;
   LPVOID lpLoaderLock;
   DWORD dwOSMajorVersion;
   DWORD dwOSMinorVersion;
   WORD wOSBuildNumber;
   WORD wOSCSDVersion;
   DWORD dwOSPlatformId;
   DWORD dwImageSubsystem;
   DWORD dwImageSubsystemMajorVersion;
   DWORD dwImageSubsystemMinorVersion;
   DWORD dwImageProcessAffinityMask;
   DWORD dwGdiHandleBuffer[34];
   LPVOID lpPostProcessInitRoutine;
   LPVOID lpTlsExpansionBitmap;
   DWORD dwTlsExpansionBitmapBits[32];
   DWORD dwSessionId;
   ULARGE_INTEGER liAppCompatFlags;
   ULARGE_INTEGER liAppCompatFlagsUser;
   LPVOID lppShimData;
   LPVOID lpAppCompatInfo;
   UNICODE_STRING usCSDVersion;
   LPVOID lpActivationContextData;
   LPVOID lpProcessAssemblyStorageMap;
   LPVOID lpSystemDefaultActivationContextData;
   LPVOID lpSystemAssemblyStorageMap;
   DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

// ===========================================================================