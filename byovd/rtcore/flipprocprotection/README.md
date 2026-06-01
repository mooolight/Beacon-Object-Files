# byovd-rtcore64-tokenconf-flipprocprotection
Flip the protection of the target process to Fully Protected Process or Process Protected Light by exploiting the vulnerable RTCore64.sys.

> This operation requires LOCAL admin privileges.

<div align='center'>
<img width="752" height="400" alt="300" src="https://github.com/user-attachments/assets/4862c025-3ae1-4863-9896-b951022ea2c9" />
</div>

## Arguments
`<targetProc>` : the target PID to modify the token configuration.  
`<prot_type>` : When flipping the process protection , choose whether to flip to Process Protection Light or Process Protection.[<pers>]: Status whether the exploited service will persist or not.  
`<pers>` : status whether the service will persist or not.  

## Usage
* `byovd-rtcore64-tokenconf-flipprocprotection <targetProc> <ppl | pp> <pers>`


## Demonstration


## Example
* `byovd-rtcore64-tokenconf-flipprocprotection <lsass|csrss>.exe ppl FALSE`

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

