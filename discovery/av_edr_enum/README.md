# av-edr-recon
Gather information about existing AV/EDR solutions in the machine.

> This operation expects that the processes to be used is already gathered in a file.

## Arguments
* `procList` : Text file containing the list of processes of known defensive solutions with the format of <procName>|<description>.

## Usage
* `av-edr-recon <procList>` 

## Demonstration


## Example
* `av-edr-recon C:\\Path\\to\\file\\..\\processes.txt`

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

