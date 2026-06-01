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

## LitterBox Testing

### Static Analysis

<img width="1563" height="513" alt="Pasted image 20260531232213" src="https://github.com/user-attachments/assets/f748ea2d-fc20-47f2-9d98-e7cfafba5cdc" />  

<img width="994" height="143" alt="Pasted image 20260531232310" src="https://github.com/user-attachments/assets/c2ce3741-affb-4b7d-8ebe-0d8a82090ea6" />  

<img width="1089" height="605" alt="Pasted image 20260531232326" src="https://github.com/user-attachments/assets/496eca57-b3dd-490e-a608-a4e071daae53" />  

<img width="947" height="379" alt="Pasted image 20260531232355" src="https://github.com/user-attachments/assets/762272f3-48f7-4223-bf8a-91da5ac38af2" />  

<img width="1305" height="642" alt="Pasted image 20260531232420" src="https://github.com/user-attachments/assets/bbb2604e-7646-4469-8c90-f940d3cc8058" />  

<img width="1351" height="580" alt="Pasted image 20260531232534" src="https://github.com/user-attachments/assets/a1c64b2a-8bd0-4c78-8a08-6889490d29f8" />  


### Dynamic Analysis


