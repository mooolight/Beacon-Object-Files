import "hash"
import "pe"                
 rule detect_unrestricttoken {
    meta:
		last_updated = "2026-06-03"
		author = "mooolight"
		description = "Yara rule for executing BYOVD attack to remove all Access Control restrictions for this process to any objects in the system."
            
    strings:
		$file_type = {4D 5A}
        $dvName = "\\Device\\RTCore64" nocase ascii wide
        $dosName = "\\DosDevices\\RTCore64" nocase ascii wide
        $drvLoad = "NtLoadDriver" nocase ascii wide
        $cmdName = "unrestricttoken" nocase ascii wide
        $driverName = "RTCore64.sys" nocase ascii wide
        $serviceName = "rtc" nocase ascii wide
        $deviceName = "\\\\.\\RTCore64" nocase ascii wide

	condition:
        //Hash values
		(hash.sha1(0,filesize) == "2fda90f6247be4062fe637e7c15b64e66861b27e") and
        (hash.md5(0,filesize) == "7352a1890a26875c2a7dc5edd5c25f6c") and
        (hash.sha256(0,filesize) == "4b8bffa6753cdac0ae19ec354042498c3e813100714896e799d53b57c3afa50f") and

        // File size : ~10k bytes
        filesize <= 174KB and 

        // Strings
        $file_type and $dvName and $dosName and $drvLoad and $cmdName and $driverName and $serviceName and $deviceName and

        // PE Imports + some functions
		(pe.imports("kernel32.dll","DeviceIoControl")) and
		(pe.imports("advapi32.dll","AdjustTokenPrivileges")) and
		(pe.imports("advapi32.dll","LookupPrivilegeValueA")) and
        (pe.imports("advapi32.dll","CreateServiceW")) and
        (pe.imports("advapi32.dll","ControlService")) and
        (pe.imports("advapi32.dll","StartServiceW")) and
        (pe.imports("advapi32.dll","OpenSCManagerW")) and

        //PE machine variables or system information
		(pe.machine == pe.MACHINE_AMD64)
 }
