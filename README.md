# Windows BOF-Collections

## Goal:
- Find a way to test a capability without having the need of the entire C2 framework.  

## Tool for Testing
- I have used COFFLoader from TrustedSec for local BOF testing.  
Link: https://github.com/trustedsec/COFFLoader  

Protections enabled during testing (as of now):  
- Compiler's Stack Buffer Overrun protection  
  > '/GS-'  
- Control Flow Guard (CFG)

## Project Direct References:
- adrenaline by atomicszec  
- atomic-bofs by Rasta-Mouse  

## Table of Contents
<div align='center'>

[Collection](#collection)  
[CredentialAccess](#credential-access)  
[Discovery](#discovery)  
[PrivilegeEscalation](#privilegeescalation)  
[BYOVD](#byovd)  
[ProcessInjection](#processinjection)  
[ActiveDirectory](#activedirectory)  
[Persistence](#persistence)  
[MalwareDelivery](#malwaredelivery)  
[ImpairingDefenses](#impairingdefenses)  
[DataExfiltration](#dataexfiltration)  
[Impact](#impact)  

<img width="633" height="350" alt="giphy" src="https://github.com/user-attachments/assets/a17d302c-b332-4e53-a381-73a78190c9c5" />

</div>



## Collection

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[procenum](collection/procenum/)**     | Finds the PID of a process name given. This operation requires appropriate privileges to see the handle to the target process object.|



## Credential Access

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[cookiecrunch](credentialaccess/cookiecrunch/)**     | Extract cookies for commonly used browsers.|
| **[edgelord](credentialaccess/edgelord/)**     | Scans msedge.exe's process and extract useful information not limited to passwords, username, url ,etc.|



## Discovery

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[tokeninfo_recon](discovery/tokeninfo_recon/)**     | Prints out target process' token attributes information such as TokenSource, TokenType, TokenImpersonationLevel, TokenSessionId, etc.|
| **[av_edr_enum](discovery/av_edr_enum/)**     | Print out artifacts that indicates the existence of security solutions in the machine. |


## BYOVD

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[rtcore-elevate2system](byovd/rtcore/elevate2system)**     | Copy the token of the System.exe process' NT AUTHORITY\SYSTEM and transferring it to the target process by exploiting the vulnerable RTCore64.sys.|
| **[rtcore-settokenhighprivs](byovd/rtcore/settokenhighprivs)**     | Setting all the privileges of a target process to '1' by exploiting the vulnerable RTCore64.sys.|
| **[rtcore-setintegritylevel](byovd/rtcore/setintegritylevel)**     | Elevate the integrity of the target process to NT AUTHORITY\SYSTEM by exploiting the vulnerable RTCore64.sys.|
| **[rtcore-unrestricttoken](byovd/rtcore/unrestricttoken)**     | Allows access of the target process to any objects in the system usually proceeded by an "access denied" due to SID restriction by exploiting the vulnerable RTCore64.sys.|
| **[rtcore-flipprocprotection](byovd/rtcore/flipprocprotection)**     | Flip the protection of the target process to Fully Protected Process or Process Protected Light by exploiting the vulnerable RTCore64.sys.|





## ProcessInjection

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[processinjection](processinjection/procinj-sectionmaps/)**     | Executes the classic process injection technique through section maps.|


## ActiveDirectory

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[dpapi-regsearch](persistence/dpapi-regsearch/)**     | Find artifacts related to DPAPI blob in the Windows Registry.|


## Persistence

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[pers-runkeys](persistence/pers-runkeys-bof/)**     | Executes the runkeys persistence technique.|

## Privilege Escalation

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[fodhelper](privilegeescalation/fodhelper/)**     | The “fodhelper UAC bypass” is a well-known Windows privilege-escalation technique that abuses the auto-elevated Microsoft binary fodhelper.exe to bypass normal User Account Control (UAC) prompts.|

## MalwareDelivery

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[dns-ptr](malwaredelivery/dns-ptr/)**     | Deliver payload into the target process' memory via DNS resolution's PTR record(s).|



## ImpairingDefenses

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[BlindingEventLog](impairingdefenses/blindingeventlog)**     | Interacting with the Event log service process to suspend logging.|
| **[EPPFirewallBlock](impairingdefenses/eppfirewallblock)**     | Blocking of Endpoint Protection Telemetry directed to its server via Firewall.|
| **[SysmonUnload](impairingdefenses/sysmonunload)**     | Unload the sysmon driver disabling endpoint telemetry.|
| **[windef-disable](impairingdefenses/windef-disable)**     | Disabling Windows Defender via Registry modification.|

## DataExFiltration

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[test](dataexfiltration/)**     | Test Test Test Test Test Test Test .|


## Impact

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[ransomware-sim-bof](impact/)**     | Executes a ransomware simulation on a proof of concept file with the most restricted access control.|


## Architecture

- Continuous Operation: A feature that runs in the background consistently (for example: object / registry callbacks).
- Semi Continuous Operation: A feature that is not running when the driver is loaded but starts after a user request and continues until driver unload or explicit cancellation (for example: IRP hooking).
- Immediate Operation: An operation with a short lifespan that returns an immediate response (for example: disabling ETW-TI).
  - Beacon-Object-Files project falls into this category.

DISCLAIMER: These beacon object files are re-creation and analysis of already known techniques. None of the techniques discussed are novel, they have been publicly known and documented by the security research community for many years, and credit is given throughout to the researchers and projects that developed them. The creators and contributors of this repository accept no liability for any loss, damage, or consequences resulting from the use of the information or code contained in this repo. By utilizing this repo, you acknowledge and accept full responsibility for your actions. Use at your own risk.
