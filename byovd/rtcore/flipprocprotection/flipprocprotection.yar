import "hash"
import "pe"

 rule detect_flipprocprotection {
    meta:
		last_updated = "2026-06-03"
		author = "mooolight"
		description = "Yara rule for executing BYOVD attack to the protection status of a process."

    strings:
		$file_type = {4D 5A}
        $dvName = "\\Device\\RTCore64" nocase ascii wide
        $dosName = "\\DosDevices\\RTCore64" nocase ascii wide
        $drvLoad = "NtLoadDriver" nocase ascii wide
        $cmdName = "flipprocprotection" nocase ascii wide
        $driverName = "RTCore64.sys" nocase ascii wide
        $serviceName = "rtc" nocase ascii wide
        $deviceName = "\\\\.\\RTCore64" nocase ascii wide

	condition:
        //Hash values
		(hash.sha1(0,filesize) == "0c373513b65cbb106810c9bd491ac66503c2391f") and
        (hash.md5(0,filesize) == "3f473ce3e6b0655104d8a3bff7b3fd1c") and
        (hash.sha256(0,filesize) == "59c36c860c407210d55b9f124b6acbcfc7dda812c57e43dea391b7b43e302e4f") and

        // File size : ~10k bytes
        filesize >= 171KB and 

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