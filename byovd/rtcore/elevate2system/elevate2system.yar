import "hash"
import "pe"

 rule detect_elevate2system {
    meta:
		last_updated = "2026-06-03"
		author = "mooolight"
		description = "Yara rule for executing BYOVD attack to elevate the privilege of a target process to SYSTEM."

    strings:
		$file_type = {4D 5A}
        $dvName = "\\Device\\RTCore64" nocase ascii wide
        $dosName = "\\DosDevices\\RTCore64" nocase ascii wide
        $drvLoad = "NtLoadDriver" nocase ascii wide
        $cmdName = "elevate2system" nocase ascii wide
        $driverName = "RTCore64.sys" nocase ascii wide
        $serviceName = "rtc" nocase ascii wide
        $deviceName = "\\\\.\\RTCore64" nocase ascii wide

	condition:
        //Hash values
		(hash.sha1(0,filesize) == "7B8523EC5970A1D9E59DA247D988837266659E97") and
        (hash.md5(0,filesize) == "BD2206C6E5C0E3AB10465D6FA0AE57C6") and
        (hash.sha256(0,filesize) == "C922BC0C97CE80CDA68E7C2943F7FDE7138043BEA50A4BFD24B1E659C6CA70F7") and

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
