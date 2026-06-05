import "hash"
import "pe"

 rule detect_settokenhighprivs {
    meta:
		last_updated = "2026-06-03"
		author = "mooolight"
		description = "Yara rule for executing BYOVD attack to enable all privileges of a process."

    strings:
		$file_type = {4D 5A}
        $dvName = "\\Device\\RTCore64" nocase ascii wide
        $dosName = "\\DosDevices\\RTCore64" nocase ascii wide
        $drvLoad = "NtLoadDriver" nocase ascii wide
        $cmdName = "settokenhighprivs" nocase ascii wide
        $driverName = "RTCore64.sys" nocase ascii wide
        $serviceName = "rtc" nocase ascii wide
        $deviceName = "\\\\.\\RTCore64" nocase ascii wide

	condition:
        //Hash values
		(hash.sha1(0,filesize) == "44a534fdef5d58a07c18a5da783343fc256926a7") and
        (hash.md5(0,filesize) == "39e029f9a44580780a4bc5cb9b3c2731") and
        (hash.sha256(0,filesize) == "b344ded6c3845ac0380b296cb70a5e3492a99523c1995250617a577610cda2f9") and

        // File size : ~10k bytes
        filesize <= 168KB and 

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
