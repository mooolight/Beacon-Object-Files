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

<img width="1395" height="639" alt="1" src="https://github.com/user-attachments/assets/25874987-e223-48af-a429-edd427838667" />  

<img width="1396" height="660" alt="2" src="https://github.com/user-attachments/assets/eba57bca-0d48-4c4d-aeb7-753ad5107f2f" />  

<img width="1394" height="293" alt="3" src="https://github.com/user-attachments/assets/7cbe70da-16f4-4f87-8473-f0f66a2f272c" />  

<img width="1485" height="419" alt="4" src="https://github.com/user-attachments/assets/02998020-58d0-4b05-858b-c3d2ac1c9afb" />  

<img width="1491" height="456" alt="5" src="https://github.com/user-attachments/assets/6df33b68-6856-4bc4-bfc0-ca0e2c75846c" />  

<img width="1486" height="475" alt="6" src="https://github.com/user-attachments/assets/1c2f91b8-8446-4950-947a-9b66cd89ab50" />  

<img width="583" height="320" alt="7" src="https://github.com/user-attachments/assets/00fb2daa-d853-4add-b5fb-fe8412ecf5e0" />  


### Dynamic Analysis

