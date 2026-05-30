# byovd-rtcore64-tokenconf-unrestricttoken
Allows access of the target process to any objects in the system usually proceeded by an "access denied" due to SID restriction by exploiting the vulnerable RTCore64.sys.  

> This operation requires LOCAL admin privileges.

<div align='center'>
<img width="780" height="464" alt="giphy" src="https://github.com/user-attachments/assets/6ee3466b-f688-4483-a0ab-1ea3377f8344" />
</div>

## Arguments
`<targetProc>` : the target PID to modify the token configuration.  
`<pers>` : status whether the service will persist or not.  

## Usage - How to not use a param? How to use different param on a different obj
* `byovd-rtcore64-tokenconf-unrestricttoken <targetProc> <pers>`

## Example
* `byovd-rtcore64-tokenconf-unrestricttoken 4928 FALSE`

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool.  // how to use Aggressor script in Powershell Empire?
