import "hash"
import "pe"

rule detect_sysmon_unload {
    meta:
		last_updated = "2026-06-04"
		author = "mooolight"
		description = "Yara rule for disabling Sysmon driver hindering Windows endpoint telemetry."

	strings:
		$file_type = {4D 5A}
        $drvName = "ofltdrv" nocase ascii wide        
        $priv = "SeLoadDriverPrivilege" nocase ascii wide
        $software = "sysmon" nocase ascii wide
        $lib = "ADVAPI32.dll" nocase ascii wide

	condition:
        // Suspicious strings from Static Analysis phase
        $drvName and $file_type and $priv and $software and $lib and
         
        // PE Imports + some functions 
		(pe.imports("advapi32.dll","OpenProcessToken")) and
		(pe.imports("advapi32.dll","LookupPrivilegeValueA")) and
        (pe.imports("advapi32.dll","AdjustTokenPrivileges")) and
        (pe.imports("advapi32.dll","GetProcAddress")) and

        //Hash values
		(hash.sha1(0,filesize) == "e4416fee50e3f98df8812723a6c2e35eeff657a7") and
        (hash.md5(0,filesize) == "210cb071f0b34ef0399cb708ea946769") and
        (hash.sha256(0,filesize) == "33819575e13e4ce7fb47c6a45712508cdb82b4d6b86e3e32af1e2bbdb4504dfe") and

        // File size : ~10k bytes
        filesize <= 141KB and

        // Machine architecture
        (pe.machine == pe.MACHINE_AMD64)
}

