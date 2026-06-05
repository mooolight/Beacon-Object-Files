# eva-eppblk-fw
Blocking of Endpoint Protection Telemetry directed to its server via Firewall.

> This operation requires appropriate privileges to the target process.

## Arguments
* `<ruleName` : Name of the rule to be displayed.
* `<ruleGroup>` : Group account to be a member of for access control.
* `<ruleDescription>` : Description of the rule.
* `<ruleApplication>` : Application to which the firewall rule will be applied to.
* `<ruleRuleRemoteAddrs>` : The remote IP address affected by the rule for either allowing or denying.

## Usage
* ` eva-eppblk-fw`


## Demonstration


## Example
* `eva-eppblk-fw <ruleName> <ruleGroup> <ruleDescription> <ruleApplication> <ruleRuleRemoteAddrs>`

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool.  // how to use Aggressor script in Powershell Empire?


## LitterBox Testing

### Static Analysis

<img width="1392" height="641" alt="1" src="https://github.com/user-attachments/assets/a2b3c1b8-e1a4-47a8-891e-0908fdecbdb5" />  

<img width="1394" height="432" alt="2" src="https://github.com/user-attachments/assets/5a25848c-816e-42ec-b4b8-0cfdd7930da4" />  

<img width="1397" height="251" alt="3" src="https://github.com/user-attachments/assets/3b29d3af-d891-4876-a9e0-a4a5e78d4c52" />  

<img width="1411" height="430" alt="4" src="https://github.com/user-attachments/assets/f6c964f0-7e66-4c37-9e15-05f50a137aa2" />  

<img width="1046" height="462" alt="5" src="https://github.com/user-attachments/assets/3dcaa65b-3a0c-41c6-9c24-c6dd7ae0c524" />  

<img width="1069" height="479" alt="6" src="https://github.com/user-attachments/assets/cf8e3521-3092-43ff-8e22-e3b12879d0d7" />  

<img width="576" height="334" alt="7" src="https://github.com/user-attachments/assets/f3d50b53-4705-48d3-bc60-11efe3e61f14" />  


### Dynamic Analysis

