# fodhelper
Executes the fodhelper binary privilege escalation technique

> This operation will work on compromised systems without hardened UAC mechanism.

## Arguments
* `<path-to-dll/exe>` : specifies the full path of the binary that will be executed with elevated privilege.
* `<cleanup>`: This is automatic for this module.


## Usage
* `fodhelper`


## Example
* `fodhelper <path-to-dll/exe>`

## Demonstration

![demo.webm](https://github.com/user-attachments/assets/2662c4a6-b536-42f9-959f-64e706c921df)




## After cleanup:
![](/assets/fodhelper-registry-aftercleanup.png)

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool. 

# Missing
- Blog post (theory) + Reversing


## LitterBox Testing

### Static Analysis


### Dynamic Analysis

