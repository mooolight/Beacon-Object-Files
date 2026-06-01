# ransomware-sim
Executes the ransomware simulation on a proof of concept file with Access Control of the highest privilege.

> This operation requires NT AUTHORITY\SYSTEM privileges.

## Arguments
* `<file-to-be-encrypted>` : specifies the <file-to-be-encrypted> given an NT AUTHORITY\SYSTEM privileges.

## Usage
* ` ransomware-sim <file-to-be-encrypted>`

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
