# byovd-rtcore64-exploit-elevate2system
Copy the token of the System.exe process' NT AUTHORITY\SYSTEM and transferring it to the target process by exploiting the vulnerable RTCore64.sys.

> This operation requires LOCAL admin privileges.

<div align='center'>
<img width="750" height="450" alt="giphy" src="https://github.com/user-attachments/assets/ecd13bb2-cedb-4b78-b3f0-5ad0f08507d1" />
</div>

## Arguments
`<targetPid>` : the target PID to modify the token configuration.  
`<pers>` : status whether the service will persist or not.  

## Usage - How to not use a param? How to use different param on a different obj
* `byovd-rtcore64-exploit-elevate2system <targetPid> <pers>`

## Example
* `byovd-rtcore64-exploit-elevate2system 8917 TRUE`

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

