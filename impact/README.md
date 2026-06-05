# ransomware-sim
Executes the ransomware simulation on a proof of concept file with Access Control of the highest privilege.

> This operation requires NT AUTHORITY\SYSTEM privileges.

## Arguments
* `<file-to-be-encrypted>` : specifies the <file-to-be-encrypted> given an NT AUTHORITY\SYSTEM privileges.

## Usage
* ` ransomware-sim <file-to-be-encrypted>`


## Demonstration


## Example
* `ransomware-sim <file-to-be-encrypted>`

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool.  // how to use Aggressor script in Powershell Empire?

# Missing
- .o file
- Demo .webm/mp4 file PoC
- Blog post (theory) + Reversing


## LitterBox Testing

### Static Analysis

<img width="1714" height="833" alt="1" src="https://github.com/user-attachments/assets/4e6a2002-a644-4898-8943-470d16702a96" />  

<img width="1697" height="723" alt="2" src="https://github.com/user-attachments/assets/2e2b59c5-aa17-44df-ae0a-391350828bf0" />  

<img width="1724" height="263" alt="3" src="https://github.com/user-attachments/assets/d4745541-6d24-467c-a31d-f7903201ed8d" />  

<img width="1684" height="447" alt="4" src="https://github.com/user-attachments/assets/1cf618d6-11c3-4c6e-aaa1-b95fca5bc3c8" />  

<img width="1217" height="496" alt="5" src="https://github.com/user-attachments/assets/5d87d9e6-601f-475a-af8a-0fe8ae73eebb" />  

<img width="846" height="78" alt="6" src="https://github.com/user-attachments/assets/d190e9f8-3463-4769-92d6-2c402f0b3b2c" />  


### Dynamic Analysis

