import "hash"
import "pe"

rule detect_windef_disable {
    meta:
		last_updated = "2026-06-04"
		author = "mooolight"
		description = "Yara rule for disabling Windows Defender through registry key/subkey tampering."

	strings:
		$file_type = {4D 5A}
        $registry = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase ascii wide        
        $str1 = "DisableAntiSpyware" nocase ascii wide
        $str2 = "Real-Time Protection" nocase ascii wide
        $str3 = "DisableRealtimeMonitoring" nocase ascii wide
        $str4 = "DisableBehaviorMonitoring" nocase ascii wide
        $str5 = "DisableScanOnRealtimeEnable" nocase ascii wide
        $str6 = "DisableOnAccessProtection" nocase ascii wide
        $str7 = "DisableIOAVProtection" nocase ascii wide

	condition:
        // Suspicious strings from Static Analysis phase
        $registry and $file_type and $str1 and $str2 and $str3 and $str4 and $str5 and $str6 and $str7 and
         
        // PE Imports + some functions 
		(pe.imports("advapi32.dll","RegCloseKey")) and
		(pe.imports("advapi32.dll","RegOpenKeyExA")) and
        (pe.imports("advapi32.dll","RegSetValueExA")) and
        (pe.imports("advapi32.dll","RegCreateKeyExA")) and
        (pe.imports("advapi32.dll","OpenProcessToken")) and

        //Hash values
		(hash.sha1(0,filesize) == "2565450cc7ca03c97262761c185103dc3058df83") and
        (hash.md5(0,filesize) == "a23b584b0040fdabbd7cedb6945aebe3") and
        (hash.sha256(0,filesize) == "f3dd21ae0dc312092ca74c1ed5dbccbd4cbb2b8c40faceb93019c489e51edab2") and

        // File size : ~10k bytes
        filesize >= 140KB and

        // Machine architecture
        (pe.machine == pe.MACHINE_AMD64)
}

