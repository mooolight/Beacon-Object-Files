# byovd-rtcore64-tokenconf-settokenhighprivs
Setting all the privileges of a target process to '1' by exploiting the vulnerable RTCore64.sys.  

> This operation requires LOCAL admin privileges.

<div align='center'>
<img width="650" height="400" alt="giphy" src="https://github.com/user-attachments/assets/75453efd-8848-4b77-bb84-23fbbfae3e74" />
</div>

## Arguments
`<targetProc>` : the target PID to modify the token configuration.  
`<pers>` : status whether the service will persist or not.  

## Usage - How to not use a param? How to use different param on a different obj
* `byovd-rtcore64-tokenconf-settokenhighprivs <targetProc> <pers>`


## Demonstration


## Example
* `byovd-rtcore64-tokenconf-settokenhighprivs 4928 FALSE`

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

<img width="1398" height="636" alt="1" src="https://github.com/user-attachments/assets/e809694b-e1a8-4b58-89ac-7d27cd08cb14" />

<img width="1399" height="642" alt="2" src="https://github.com/user-attachments/assets/fd46d3aa-8433-48e6-b4e9-13fd924127f9" />

<img width="1397" height="593" alt="3" src="https://github.com/user-attachments/assets/c037fda1-8ca5-4293-bf50-95b50a2eaedb" />

<img width="1395" height="257" alt="4" src="https://github.com/user-attachments/assets/b29a72fc-f47d-486d-a28a-e0baf10d70a4" />

<img width="1389" height="436" alt="5" src="https://github.com/user-attachments/assets/c2dff627-8b92-4569-8ae4-a29ae3fdaab0" />

<img width="1100" height="471" alt="6" src="https://github.com/user-attachments/assets/6cce7e2b-86a9-4bea-8401-b064d17ae232" />

<img width="1044" height="479" alt="7" src="https://github.com/user-attachments/assets/a8fe6471-a1c6-46f3-85ff-5a1fbbe138f6" />

<img width="615" height="337" alt="8" src="https://github.com/user-attachments/assets/b9e41c73-d757-4590-9e96-8da5d2c278bb" />


### Dynamic Analysis
