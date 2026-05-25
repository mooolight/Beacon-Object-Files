# Windows BOF-Collections

## Tool for Testing
- I have used COFFLoader from TrustedSec for local BOF testing.
- Link: https://github.com/trustedsec/COFFLoader


<div align='center'>

## Table of Contents

[Collection](#collection)  
[Credential Access](#credential-access)  
[Discovery](#discovery)  
[PrivilegeEscalation](#privilegeescalation)  
[Execution](#execution)  
[BYOVD](#byovd)  
[ProcessInjection](#processinjection)  
[ActiveDirectory](#activedirectory)  
[Persistence](#persistence)  
[PrivilegeEscalation](#privilegeescalation)  
[Impact](#impact)  
[ImpairingDefenses](#impairingdefenses)  


</div>

## Collection

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[procenum](collection/procenum/)**     | Finds the PID of a process name given. This operation requires appropriate privileges to see the handle to the target process object.|



## Credential Access

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[cookiecrunch](credentialaccess/cookiecrunch/)**     | Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test .|


## Discovery

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[tokeninfo_recon](discovery/tokeninfo_recon/)**     | Prints out target process' token attributes information such as TokenSource, TokenType, TokenImpersonationLevel, TokenSessionId, etc.|
| **[av_edr_enum](discovery/av_edr_enum/)**     | Print out artifacts that indicates the existence of security solutions in the machine. |


## Execution

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[warbird](execution/warbird/)**     | Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test .|


## BYOVD

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[RTCore](byovd/rtcore/)**     | Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test .|


## Process Injection

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[processinjection](processinjection/procinj-sectionmaps/)**     | Executes the classic process injection technique through section maps.|


## Active Directory

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[registry](persistence/registry/)**     | Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test .|


## Persistence

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[pers-runkeys](persistence/pers-runkeys-bof/)**     | Executes the runkeys persistence technique.|

## Privilege Escalation

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[fodhelper](privilegeescalation/fodhelper/)**     | The “fodhelper UAC bypass” is a well-known Windows privilege-escalation technique that abuses the auto-elevated Microsoft binary fodhelper.exe to bypass normal User Account Control (UAC) prompts.|


## Impairing Defenses

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[sample](impairingdefenses/sample)**     | Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test Test .|

## Impact

| **BOF**                  | **Use**                                                                                                                                                         |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **[ransomware-sim-bof](impact/)**     | Executes a ransomware simulation on a proof of concept file with the most restricted access control.|


DISCLAIMER: The creators and contributors of this repository accept no liability for any loss, damage, or consequences resulting from the use of the information or code contained in this repo. By utilizing this repo, you acknowledge and accept full responsibility for your actions. Use at your own risk.
