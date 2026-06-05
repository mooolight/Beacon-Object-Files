# eva-sysmon-unload
Unload the sysmon driver as well as disabling the process running it.

> This operation requires appropriate privileges to the target process for access.

## Arguments
None

## Usage
* `eva-sysmon-unload`

## Example
* `eva-sysmon-unload`


## Demonstration


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

<img width="1391" height="639" alt="1" src="https://github.com/user-attachments/assets/4801edb6-13da-48de-8bd3-19a30eee0359" />  

<img width="1393" height="592" alt="2" src="https://github.com/user-attachments/assets/c54c0a54-a76b-48cc-aa73-7924795cc297" />  

<img width="1396" height="255" alt="3" src="https://github.com/user-attachments/assets/6c4d76fa-8377-4407-ada5-7116e78f8e0d" />  

<img width="1440" height="444" alt="4" src="https://github.com/user-attachments/assets/b95888e6-928e-41c9-9daf-6429b1a1f1ac" />  

<img width="1156" height="515" alt="5" src="https://github.com/user-attachments/assets/c2561f46-78be-42ce-bd11-0b8e5d248bfb" />  

<img width="1029" height="473" alt="6" src="https://github.com/user-attachments/assets/1c0bedd5-0e04-4585-b39c-a5750ddf5360" />  

<img width="553" height="323" alt="7" src="https://github.com/user-attachments/assets/589babd0-3a22-4f83-8f1a-737ecbf8b7a1" />  


### Dynamic Analysis

