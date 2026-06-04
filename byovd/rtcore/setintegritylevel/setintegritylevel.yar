import "hash"
import "pe"

 rule detect_setintegritylevel {
    meta:
		last_updated = "2026-06-03"
		author = "mooolight"
		description = "Yara rule for executing BYOVD attack to set the integrity of the process to SYSTEM."

    strings:
		$file_type = {4D 5A}
        $dvName = "\\Device\\RTCore64" nocase ascii wide
        $dosName = "\\DosDevices\\RTCore64" nocase ascii wide
        $drvLoad = "NtLoadDriver" nocase ascii wide
        $cmdName = "setintegritylevel" nocase ascii wide
        $driverName = "RTCore64.sys" nocase ascii wide
        $serviceName = "rtc" nocase ascii wide
        $deviceName = "\\\\.\\RTCore64" nocase ascii wide

	condition:
        //Hash values
		(hash.sha1(0,filesize) == "ff9c9dcef7adc4e5163e116bd65f0cbe46bd44f7") and
        (hash.md5(0,filesize) == "ee72e5883b0ed2941f50d2aa317776f8") and
        (hash.sha256(0,filesize) == "ff95cd7b319855b2f33ea3a5f1872fc2c24bfb8a4aeb3781b80ad9e2b785ede7") and

        // File size : ~10k bytes
        filesize >= 170KB and 

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