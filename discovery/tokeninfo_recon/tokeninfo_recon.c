/*
	Author: @mooolight
	Function: Token information recon through the implant on the target machine.
	NOTE: Dont forget to change 1st arg of BeaconPrintf to BeaconOutput instead when used with Empire.
*/

#include "tokeninfo_recon-imports.h"
#include "tokeninfo_recon-structs.h"

/* ACE Types:
ACCESS_ALLOWED_ACE_TYPE                      Access-allowed ACE that uses the ACCESS_ALLOWED_ACE structure. 
ACCESS_ALLOWED_CALLBACK_ACE_TYPE             Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE structure. 
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE      Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE structure. 
ACCESS_ALLOWED_COMPOUND_ACE_TYPE             Reserved. 
ACCESS_ALLOWED_OBJECT_ACE_TYPE               Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE structure. 
ACCESS_DENIED_ACE_TYPE                       Access-denied ACE that uses the ACCESS_DENIED_ACE structure. 
ACCESS_DENIED_CALLBACK_ACE_TYPE              Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE structure. 
ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE       Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE structure. 
ACCESS_DENIED_OBJECT_ACE_TYPE                Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE structure. 
ACCESS_MAX_MS_ACE_TYPE                       Same as SYSTEM_ALARM_OBJECT_ACE_TYPE. 
ACCESS_MAX_MS_V2_ACE_TYPE                    Same as SYSTEM_ALARM_ACE_TYPE. 
ACCESS_MAX_MS_V3_ACE_TYPE                    Reserved. 
ACCESS_MAX_MS_V4_ACE_TYPE                    Same as SYSTEM_ALARM_OBJECT_ACE_TYPE. 
ACCESS_MAX_MS_OBJECT_ACE_TYPE                Same as SYSTEM_ALARM_OBJECT_ACE_TYPE. 
ACCESS_MIN_MS_ACE_TYPE                       Same as ACCESS_ALLOWED_ACE_TYPE. 
ACCESS_MIN_MS_OBJECT_ACE_TYPE                Same as ACCESS_ALLOWED_OBJECT_ACE_TYPE. 
SYSTEM_ALARM_ACE_TYPE                        Reserved for future use. System-alarm ACE that uses the SYSTEM_ALARM_ACE structure. 
SYSTEM_ALARM_CALLBACK_ACE_TYPE               Reserved for future use. System-alarm callback ACE that uses the SYSTEM_ALARM_CALLBACK_ACE structure. 
SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE        Reserved for future use. Object-specific system-alarm callback ACE that uses the SYSTEM_ALARM_CALLBACK_OBJECT_ACE structure. 
SYSTEM_ALARM_OBJECT_ACE_TYPE                 Reserved for future use. Object-specific system-alarm ACE that uses the SYSTEM_ALARM_OBJECT_ACE structure. 
SYSTEM_AUDIT_ACE_TYPE                        System-audit ACE that uses the SYSTEM_AUDIT_ACE structure. 
SYSTEM_AUDIT_CALLBACK_ACE_TYPE               System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE structure. 
SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE        Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE structure. 
SYSTEM_AUDIT_OBJECT_ACE_TYPE                 Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE structure. 
SYSTEM_MANDATORY_LABEL_ACE_TYPE              0x11 
*/
//void PrintAce(PACE_HEADER pAceHeader) {  // idk what's wrong with this function. It doesnt work as a BOF
	/*
	typedef struct _ACE_HEADER {
	  BYTE AceType;
	  BYTE AceFlags;
	  WORD AceSize;
	} ACE_HEADER;
	
	typedef struct _ACCESS_ALLOWED_ACE {
	  ACE_HEADER  Header;
	  ACCESS_MASK Mask;
	  DWORD       SidStart;
	} ACCESS_ALLOWED_ACE;
	*/
	
	// Lookup Account name from SID
/*	WCHAR name[256], domain[256];
	DWORD nameLen = 256, domainLen = 256;
	SID_NAME_USE sidType;
	if(pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE){
		PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)pAceHeader;
		
		// Get SID Pointer
		PSID pSid = (PSID)&pAllowedAce->SidStart;
		
		if(ADVAPI32$LookupAccountSidA(NULL, pSid, name, &nameLen, domain, &domainLen, &sidType))
			BeaconPrintf(CALLBACK_OUTPUT ,"ACE: Allow- %s\\%s - Access Mask: 0x%08X\n", domain, name, pAllowedAce->Mask);
		else
			PRINT("ACE: Allow - Unknown SID - Access Mask: 0x%08X\n",pAllowedAce->Mask);
	} else if(pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
		PACCESS_DENIED_ACE pDeniedAce = (PACCESS_DENIED_ACE)pAceHeader;
		PSID pSid = (PSID)&pDeniedAce->SidStart;
		
		if(ADVAPI32$LookupAccountSidA(NULL, pSid, name, &nameLen, domain, &domainLen, &sidType))
			PRINT("ACE: Deny- %s\\%s - Access Mask: 0x%08X\n", domain, name, pDeniedAce->Mask);
		else
			PRINT("ACE: Deny - Unknown SID - Access Mask: 0x%08X\n",pDeniedAce->Mask);
	} else
		PRINT("ACE: Type 0x%02X not handled\n", pAceHeader->AceType);

	return;
}*/

//void Print


void PrintSIDType(SID_NAME_USE use){
	switch (use) {
		case SidTypeUser:
			PRINT("[+] SID Use case: A user SID.\n");
			break;
		case SidTypeGroup:
			PRINT("[+] SID Use case: A group SID.\n");
			break;
		case SidTypeDomain: 
			PRINT("[+] SID Use case: A domain SID.\n");
			break;
		case SidTypeAlias:
			PRINT("[+] SID Use case: An alias SID.\n");
			break;
		case SidTypeWellKnownGroup:
			PRINT("[+] SID Use case: A SID for a well-known group.\n");
			break;
		default:
			break;
	}
	return;
}


void PrintTokenUserInformation(HANDLE hToken, HANDLE hHeap, SID_NAME_USE use) {
	// Get token info after extracting the handle - this populates the 'size' variable and estimates the TOKEN_USER structure size.
	// 1st arg: Handle to the opened process' token
	// 2nd arg: From _TOKEN_INFORMATION_CLASS. The buffer receives a TOKEN_USER structure that contains the user account of the token 
	// 3rd arg: pointer of the SID because the actual size of the SID is bigger
	TOKEN_USER user;
	DWORD token_usersize = sizeof(TOKEN_USER);
	
	GetTokenInformation(hToken, TokenUser, 0, 0, &token_usersize);
	
	// Token User size: 12 bytes (SID_AND_ATTRIBUTES = [PSID(8bytes) / PISID(8bytes) + DWORD (4bytes)])
	PRINT("[+] Token User size information: %d\n" , token_usersize);
	if(!token_usersize) {
		PRINT("[-] Failed to get the token information...\n");
		CloseHandle(hToken);
		return FALSE;
	}
	
	PTOKEN_USER pTokenUser = NULL;
	pTokenUser = (PTOKEN_USER)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,token_usersize);
	if(pTokenUser == NULL) {
		PRINT("[-] HeapAlloc failed.\n");
		CloseHandle(hToken);
		return FALSE;
	}
	PRINT("Starting address for the Token User: 0x%-016p\n", pTokenUser);
	
	// This extracts the SID blob for the User
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, token_usersize, &token_usersize)) {    // last param is mandatory
		CloseHandle(hToken);
		return FALSE;
	}

	LPSTR sid = NULL;
	// Validating the SID extracted:
	if(!IsValidSid(pTokenUser->User.Sid)){
		PRINT("[-] GetTokenInformation (data) failed. Error: %lu\n", GetLastError());
		LocalFree(pTokenUser);
		CloseHandle(hToken);
		return FALSE;
	}
	PRINT("[+] Successfully validated the SID!\n", GetLastError());
	
	
	// Extract either SID or Attributes
	if(!ConvertSidToStringSidA(pTokenUser->User.Sid, &sid)) {
		PRINT("[-] Failed to extract the string version of SID.\n");
		DWORD dwError = GetLastError();
		PRINT("ConvertSidToStringSidA failed. Error: %lu.\n\n", dwError);
		LocalFree(sid);
		CloseHandle(hToken);
		return FALSE;
	}
	
	PRINT("[+] Successfully extracted the string version of SID.\n");
	PRINT("[+] SID: %s\n", sid);
	if(LocalFree(sid) != NULL) {
		PRINT("[-] Cannot free the TOKEN_USER structure.\n");
		CloseHandle(hToken);
		return FALSE;
	}
	
	// Get the user name
	char username[32];
	char domain[32];
	
	DWORD lusername = sizeof(username), ldomain = sizeof(domain);
	
	/*BOOL LookupAccountSidA(
	  LPCSTR        lpSystemName,
	  PSID          Sid,
	  LPSTR         Name,
	  LPDWORD       cchName,
	  LPSTR         ReferencedDomainName,
	  LPDWORD       cchReferencedDomainName,
	  PSID_NAME_USE peUse
	);*/
	if(!LookupAccountSidA(NULL, pTokenUser->User.Sid, username, &lusername, domain, &ldomain, &use)) { // pls give me the name and domain name that corresponds to that SID
		PRINT("Failed to extract the SID name...\n");
		CloseHandle(hToken);
		return FALSE;
	}
	PRINT("[+] Domain\\Username: %s\\%s\n", domain, username);
	PrintSIDType(use);
	
	// Other General Token info you might want to know...
	TOKEN_STATISTICS stats;
	if(GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &token_usersize)) {
		PRINT("\nToken Type: %s\n", stats.TokenType == TokenPrimary ? "[+] Primary Token\n\n" : "[*] Impersonation\n\n");
	}
	
	return;
}


void PrintTokenGroups(HANDLE hToken) {
	// Print Token Groups
	TOKEN_GROUPS tkgroups;
	DWORD tkgrp_size = sizeof(TOKEN_GROUPS);
	PTOKEN_GROUPS ptkgroups = (PTOKEN_GROUPS) &tkgroups;
	
	// Extracting the Token Groups for the token of the current process
	GetTokenInformation(hToken, TokenGroups, 0, 0, &tkgrp_size);
	
	// Expected tkgrp_size == 24 ; 2*DWORD(4bytes) + PSID(8bytes) + PISID (8bytes)
	PRINT("[+] Token group size information: %d\n" , tkgrp_size);
	
	// This extracts the SID blob for the User
    if (!GetTokenInformation(hToken, TokenGroups, &tkgroups, tkgrp_size, &tkgrp_size)) {    // last param is mandatory
		CloseHandle(hToken);
		return FALSE;
	}
	
	PRINT("\n[+] Number of groups in the access token: %lu\n", ptkgroups->GroupCount);
	//free(ptkgroups);
	return;
}


void PrintTokenPrivileges(HANDLE hToken) {
	PRINT("\nGetting information about Token Privileges...\n");
	TOKEN_PRIVILEGES tkprivs;
	DWORD tkprivs_size = sizeof(TOKEN_PRIVILEGES);
	PTOKEN_PRIVILEGES ptkprivs = (PTOKEN_PRIVILEGES) &tkprivs;
	GetTokenInformation(hToken, TokenPrivileges, 0, 0, &tkprivs_size);

	if (!GetTokenInformation(hToken, TokenPrivileges, &tkprivs, tkprivs_size, &tkprivs_size)) {    // last param is mandatory
		CloseHandle(hToken);
		return FALSE;
	}
	
	PRINT("[+] Privilege Count : %lu\n", ptkprivs->PrivilegeCount);
	//free(ptkprivs);
	return;
}


void PrintTokenOwner(HANDLE hToken,SID_NAME_USE use) {
	PRINT("\nGetting information about Token Owner...\n");
	TOKEN_OWNER tk_owner;
	DWORD tk_owner_size = sizeof(TOKEN_OWNER);
	PTOKEN_OWNER ptk_owner = (PTOKEN_OWNER) &tk_owner; // Use the SID "ptk_owner->Owner"
	LPSTR ownerSID = NULL;
	BOOL result = GetTokenInformation(hToken, TokenOwner, 0, 0, &tk_owner_size);
	
	if (!GetTokenInformation(hToken, TokenOwner, &tk_owner, tk_owner_size, &tk_owner_size)) {    // last param is mandatory
		CloseHandle(hToken);
		PRINT("[-] Failed to extract the Token Owner information...\n");
		return FALSE;
	}
	
	// Extract either SID or Attributes for the Token Owner
	if(!ConvertSidToStringSidA(ptk_owner->Owner, &ownerSID)) {
		PRINT("[-] Failed to extract the string version of Owner SID.\n");
		DWORD dwError = GetLastError();
		PRINT("ConvertSidToStringSidA failed. Error: %lu.\n\n", dwError);
		LocalFree(ownerSID);
		CloseHandle(hToken);
		//free(ptk_owner);
		return FALSE;
	}
	PRINT("[+] TokenOwner SID : %s\n", ownerSID);
	
	char own_domain[32];
	char own_user[32];
	DWORD own_lusername = sizeof(own_user), own_ldomain = sizeof(own_domain);

	if(!LookupAccountSidA(NULL, ptk_owner->Owner, own_user, &own_lusername, own_domain, &own_ldomain, &use)) { // pls give me the name and domain name that corresponds to that SID
		PRINT("Failed to extract the SID name...\n");
		CloseHandle(hToken);
		return FALSE;
	}
	
	PRINT("[+] Domain\\Username: %s\\%s\n", own_user, own_domain);
	//free(ptk_owner);
	return;
}


void PrintTokenPrimaryGroup(HANDLE hToken, SID_NAME_USE use){
	PRINT("\nGetting information about Token's Primary Group...\n");
	TOKEN_PRIMARY_GROUP tk_primaryGroup;
	DWORD tk_primaryGroup_size = sizeof(TOKEN_PRIMARY_GROUP);
	PTOKEN_PRIMARY_GROUP ptk_primaryGroup = (PTOKEN_PRIMARY_GROUP) &tk_primaryGroup;
	BOOL result = GetTokenInformation(hToken, TokenPrimaryGroup, 0, 0, &tk_primaryGroup_size);
	LPSTR grpSID = NULL;
	
	if (!GetTokenInformation(hToken, TokenPrimaryGroup, &tk_primaryGroup, tk_primaryGroup_size, &tk_primaryGroup_size)) {    // last param is mandatory
		CloseHandle(hToken);
		PRINT("[-] Failed to extract the Token Primary Group information...");
		return FALSE;
	}
	
	// Extract either SID or Attributes for the Token Primary Group
	if(!ConvertSidToStringSidA(ptk_primaryGroup->PrimaryGroup, &grpSID)) {
		PRINT("[-] Failed to extract the string version of Owner SID.\n");
		DWORD dwError = GetLastError();
		PRINT("ConvertSidToStringSidA failed. Error: %lu.\n\n", dwError);
		LocalFree(grpSID);
		CloseHandle(hToken);
		//MSVCRT$free(ptk_primaryGroup);
		return FALSE;
	}
	PRINT("[+] TokenOwner SID : %s\n", grpSID);
	
	char grp_domain[32];
	char grp_user[32];
	DWORD grp_lusername = sizeof(grp_user), grp_ldomain = sizeof(grp_domain);

	if(!LookupAccountSidA(NULL, ptk_primaryGroup->PrimaryGroup, grp_user, &grp_lusername, grp_domain, &grp_ldomain, &use)) { // pls give me the name and domain name that corresponds to that SID
		PRINT("Failed to extract the SID name...\n");
		CloseHandle(hToken);
		return FALSE;
	}
	PRINT("[+] Domain\\Username: %s\\%s\n", grp_user, grp_domain);
	//free(ptk_primaryGroup);
	return;
}


void PrintTokenDefaultDacl(HANDLE hToken) {
	PRINT("\nGetting information about Token's Default DACL...\n");
	TOKEN_DEFAULT_DACL tk_defdacl;
	DWORD tk_defdacl_size = sizeof(TOKEN_DEFAULT_DACL);
	ACL_SIZE_INFORMATION aclSizeInfo = {0};
	PTOKEN_DEFAULT_DACL ptk_defdacl = (PTOKEN_DEFAULT_DACL) &tk_defdacl;
	BOOL result = GetTokenInformation(hToken, TokenDefaultDacl, 0, 0, &tk_defdacl_size);
	LPSTR defDaclSID = NULL;
	
	if (!GetTokenInformation(hToken, TokenDefaultDacl, &tk_defdacl, tk_defdacl_size, &tk_defdacl_size)) {    // last param is mandatory
		CloseHandle(hToken);
		PRINT("[-] Failed to extract the Token Default DACL information...");
		return FALSE;
	}
	PRINT("[+] Initialized the default DACL...\n");
	
	// APIs to be used: GetAclInformation, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, IsValidAcl - Not sure why it doesnt work
	/*
		if(!ADVAPI32$IsValidAcl(((PACL)(ptk_defdacl->DefaultDacl)))) {
			PRINT("[-] DACL is invalid!\n");
			KERNEL32$CloseHandle(hToken);
			return FALSE;
		}
		PRINT("[+] DACL is valid!\n");
	*/
	
	PRINT("[+] ACL contains %lu ACEs\n", ptk_defdacl->DefaultDacl->AceCount);
	/*
	for(int i =0; i < ptk_defdacl->DefaultDacl->AceCount; i++) {
		LPVOID pAce = NULL; // pointer holder for every ACE in the ACL	
		
		if(ADVAPI32$GetAce(ptk_defdacl->DefaultDacl,i,&pAce))
			PrintAce((PACE_HEADER)pAce); // Prints the ACE
		else
			printf("GetAce failed at index %lu: %lu\n", i, KERNEL32$GetLastError());
	}
	*/
	
	//MSVCRT$free(ptk_defdacl);
	return;
}


BOOL DisplayTokenInfo(DWORD pid) {
	BOOL result;
	SID_NAME_USE use = {0};
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!hProcess)
		return FALSE;
	
	TOKEN_ELEVATION elevation;
	DWORD tkelev_size = sizeof(TOKEN_ELEVATION);
	HANDLE hToken = NULL;
	HANDLE hHeap = GetProcessHeap();
	
	// Protected processes dont provide the ability to open a handle - cant access a token for protected processes basically
	if(!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) // Gets the primary token of a process
		return FALSE;
	
	PRINT("[+] Token of the process: 0x%-016p\n", hToken);

	// Extracting the elevation level for the token of the current process
	result = GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &tkelev_size);
	PRINT("\nIs the token elevated?\n %s \n", elevation.TokenIsElevated != 0 ? "[+] Token is elevated!\n" : "[-] Token has medium integrity...\n");

	// Print Token User Information
	PrintTokenUserInformation(hToken,hHeap,use);
	
	// Print Token Group Information
	PrintTokenGroups(hToken);
	
	// Print Token Privileges
	PrintTokenPrivileges(hToken);
	
	PRINT("Hello world...\n");
	
	// Print Token Owner Information
	PrintTokenOwner(hToken, use);
	
	// Print Token Primary Group Information
	PrintTokenPrimaryGroup(hToken, use);
	
	// Goal: Extracts the number of ACEs in an ACL along with the type (Deny/Allow) + <domain>\<user> + <access-mask>
	PrintTokenDefaultDacl(hToken);
	
	PRINT("\nGetting information about Token's Source...\n");
	TOKEN_SOURCE tk_src;
	DWORD tk_src_size = sizeof(TOKEN_SOURCE);
	PTOKEN_SOURCE ptk_src = (PTOKEN_SOURCE) &tk_src;
	result = GetTokenInformation(hToken, TokenSource, 0, 0, &tk_src_size);
	
	if(!GetTokenInformation(hToken, TokenSource, &tk_src, tk_src_size, &tk_src_size)) {    // last param is mandatory
		CloseHandle(hToken);
		PRINT("[-] Failed to extract the Token Source information: %lu", GetLastError());
		return FALSE;
	}
	PRINT("[+] Token Source: %s\n", ptk_src->SourceName);
	ULONGLONG fullLuid = ((ULONGLONG)ptk_src->SourceIdentifier.HighPart << 32) | ptk_src->SourceIdentifier.LowPart;
	PRINT("Source LUID: 0x%016llX (%llu)\n", fullLuid, fullLuid);   // in hex and in decimal respectively
	
	
	/*
	  TokenSource,                  // this
	  TokenType,   					// this
	  TokenImpersonationLevel,   	// this
	  TokenStatistics,
	  TokenRestrictedSids,
	  TokenSessionId,   			// this
	  TokenGroupsAndPrivileges,   	// this
	  TokenSessionReference,
	  TokenSandBoxInert,
	  TokenAuditPolicy,
	  TokenOrigin,   				// this
	  TokenElevationType,   		// this
	  TokenLinkedToken,
	  TokenHasRestrictions,   		// this
	  TokenAccessInformation,
	  TokenVirtualizationAllowed,
	  TokenVirtualizationEnabled,
	  TokenIntegrityLevel,   		// this
	  TokenUIAccess,
	  TokenMandatoryPolicy,   		// this
	  TokenLogonSid,   				// this
	  TokenIsAppContainer,
	  TokenCapabilities,   			// this
	  TokenAppContainerSid,
	  TokenAppContainerNumber,
	  TokenUserClaimAttributes,
	  TokenDeviceClaimAttributes,
	  TokenRestrictedUserClaimAttributes,
	  TokenRestrictedDeviceClaimAttributes,
	  TokenDeviceGroups,
	  TokenRestrictedDeviceGroups,
	  TokenSecurityAttributes,   	// this
	  TokenIsRestricted,   			// this
	  TokenProcessTrustLevel,
	  TokenPrivateNameSpace,
	  TokenSingletonAttributes,
	  TokenBnoIsolation,
	  TokenChildProcessFlags,   	// this
	  TokenIsLessPrivilegedAppContainer,
	  TokenIsSandboxed,   					// this
	  TokenOriginatingProcessTrustLevel,   // this
	  MaxTokenInfoClass
*/

	//MSVCRT$free(ptkgroups);
	//MSVCRT$free(ptkprivs);
	CloseHandle(hToken);
	return TRUE;
}


#ifdef BOF

// Usage: tokeninfo_recon <targetProc>
void go(char *args, int alen) {
	datap parser;
	char* targetProc;
	
	// Prepare data parser
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	targetProc = BeaconDataExtract(&parser, NULL);
	
	PRINT("User input Target process: %s\n", targetProc);
	
	DWORD pid = GetCurrentProcessId();

	PRINT("[+] Extracted PID:%d\n",pid);
//	PRINT("Sleeping for a few seconds...\n");
//	Sleep(3000);
//	PRINT("Wakey wakey!\n");

	PRINT("Opening a handle to the current process...\n");
	DWORD curProcHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	PRINT("[+] Process Handle: 0x%-016p\n",curProcHandle);
	
	PRINT("============================================================ Token Information ============================================================\n");
	BOOL res = DisplayTokenInfo(pid);
	if(!res) {
		PRINT("[-] Failed to get the token info on the COFF loader's process!\n");
		PRINT("===========================================================================================================================================");
		return;
	}
	PRINT("[+] Successfully extracted the token information for the current process.\n");
	PRINT("===========================================================================================================================================");
	return;
}


#else

int main(){
	char* targetProc = "calculator.exe";
	
	PRINT("User input Target process: %s\n", targetProc);
	
	DWORD pid = GetCurrentProcessId();

	PRINT("[+] Extracted PID:%d\n",pid);
//	PRINT("Sleeping for a few seconds...\n");
//	Sleep(3000);
//	PRINT("Wakey wakey!\n");

	PRINT("Opening a handle to the current process...\n");
	DWORD curProcHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	PRINT("[+] Process Handle: 0x%-016p\n",curProcHandle);
	
	PRINT("============================================================ Token Information ============================================================\n");
	BOOL res = DisplayTokenInfo(pid);
	if(!res) {
		PRINT("[-] Failed to get the token info on the COFF loader's process!\n");
		PRINT("===========================================================================================================================================");
		return;
	}
	PRINT("[+] Successfully extracted the token information for the current process.\n");
	PRINT("===========================================================================================================================================");
	return 0;
}

#endif