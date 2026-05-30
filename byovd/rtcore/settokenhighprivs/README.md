# byovd-rtcore64-tokenconf-settokenhighprivs
Capabilities not limited to elevating the target process' token similar to SYSTEM.exe through modification of kernel memory with the help of the RTCore64.sys vulnerable driver.

> This operation requires LOCAL admin privileges.

## Arguments
`<targetProc>` : the target PID to modify the token configuration.
`<pers>` : status whether the service will persist or not.

## Usage - How to not use a param? How to use different param on a different obj
* `byovd-rtcore64-tokenconf-settokenhighprivs <targetProc> <pers>`

## Example
* `byovd-rtcore64-tokenconf-settokenhighprivs 4928 FALSE`

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool.  // how to use Aggressor script in Powershell Empire?
