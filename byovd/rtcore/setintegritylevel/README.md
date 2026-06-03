# byovd-rtcore64-tokenconf-setintegritylevel
Elevate the integrity of the target process to NT AUTHORITY\SYSTEM by exploiting the vulnerable RTCore64.sys.  

> This operation requires LOCAL admin privileges.

<div align='center'>
<img width="756" height="400" alt="200" src="https://github.com/user-attachments/assets/3b5a0539-d370-4ed1-9ca1-040ffeb381eb" />
</div>

## Arguments
`<targetProc>` : the target PID to modify the token configuration.  
`<pers>` : status whether the service will persist or not.  

## Usage - How to not use a param? How to use different param on a different obj
* `byovd-rtcore64-tokenconf-setintegritylevel <targetProc> <pers>`


## Demonstration


## Example
* `byovd-rtcore64-tokenconf-setintegritylevel 4928 FALSE`

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

<img width="1396" height="640" alt="1" src="https://github.com/user-attachments/assets/b37ee9cd-d2da-42fc-ba94-45c102a12634" />

<img width="1390" height="640" alt="2" src="https://github.com/user-attachments/assets/c56afc18-4f81-442e-b650-5dc3f446800c" />

<img width="1393" height="593" alt="3" src="https://github.com/user-attachments/assets/81a75ca3-48a3-4d9a-b660-fb1f37e887b0" />

<img width="1395" height="253" alt="4" src="https://github.com/user-attachments/assets/b2315158-907a-4beb-ba9f-d452804e696e" />

<img width="1400" height="430" alt="5" src="https://github.com/user-attachments/assets/47f89d8e-2974-4fbc-b577-f727590c7eea" />

<img width="1346" height="475" alt="6" src="https://github.com/user-attachments/assets/fa1136f4-c8a0-4d9f-a6b4-862ea300b086" />

<img width="1204" height="468" alt="7" src="https://github.com/user-attachments/assets/82140698-b456-4a65-b52e-8123b13ea7fb" />

<img width="631" height="374" alt="8" src="https://github.com/user-attachments/assets/d2039350-a3fc-4222-a373-7eb8c7ddf4a4" />



### Dynamic Analysis

