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


## Demonstration


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

<img width="1572" height="544" alt="Pasted image 20260602185307" src="https://github.com/user-attachments/assets/65d6fb4b-671f-4ca2-a017-36d8ad43dfb8" />

<img width="1380" height="561" alt="Pasted image 20260602185327" src="https://github.com/user-attachments/assets/3cf999ef-f41e-487a-a7a4-f947398dc99f" />

<img width="1397" height="656" alt="Pasted image 20260602185352" src="https://github.com/user-attachments/assets/fbb21716-890e-4a00-a711-cd28c5b35761" />

<img width="1398" height="545" alt="Pasted image 20260602185410" src="https://github.com/user-attachments/assets/a6bc90f6-ef6b-4ebe-95f6-1e1eb404cfdf" />


### Dynamic Analysis

