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

<img width="545" height="333" alt="1" src="https://github.com/user-attachments/assets/767ec6bb-a55e-4075-8493-00be137bdcaf" />

<img width="1055" height="470" alt="2" src="https://github.com/user-attachments/assets/3645c5e7-bb3c-4d8a-8e66-947eb5bc2384" />

<img width="1074" height="453" alt="3" src="https://github.com/user-attachments/assets/881f73fa-4eb1-41b2-a2a9-9182ff899eea" />

<img width="1587" height="427" alt="4" src="https://github.com/user-attachments/assets/2e0607f3-a496-4b92-9d9c-1a345c7296ca" />

<img width="1391" height="638" alt="8" src="https://github.com/user-attachments/assets/af82ca04-765c-4900-af1f-2689eb266abd" />

<img width="1390" height="588" alt="7" src="https://github.com/user-attachments/assets/fa53b6a4-161d-4e12-ac04-a9461987574a" />

<img width="1392" height="645" alt="6" src="https://github.com/user-attachments/assets/fe43dc05-604f-4868-89aa-e011150e4d8f" />

<img width="1396" height="447" alt="5" src="https://github.com/user-attachments/assets/4a7d039e-f130-41cb-bab7-cf3ab70f95be" />


### Dynamic Analysis

