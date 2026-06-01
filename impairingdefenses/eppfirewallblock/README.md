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


### Dynamic Analysis

