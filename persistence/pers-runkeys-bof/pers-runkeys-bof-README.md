# pers-sethc
Executes the runkeys persistence technique

> This operation requires elevated privileges.

## Arguments
* `<path-to-exe>` : specifies the full path that will be executed through the persistence mechanism.


## Usage
* `pers-runkeys-bof`


## Example
* `pers-runkeys-bof <path-to-exe>`

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool.  // how to use Aggressor script in Powershell Empire?