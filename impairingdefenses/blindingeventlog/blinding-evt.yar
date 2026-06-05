import "hash"
import "pe"

rule detect_blinding_evt {
    meta:
		last_updated = "2026-06-04"
		author = "mooolight"
		description = "Yara rule for blocking Windows Event logs."

	strings:
		$file_type = {4D 5A}     
        $priv = "SeDebugPrivilege" nocase ascii wide    
        $prov = "EventLog" nocase ascii wide    
        $lib = "ADVAPI32.dll" nocase ascii wide 
        $func = "I_QueryTagInformation" nocase ascii wide   

	condition:
        // Suspicious strings from Static Analysis phase
        $file_type and $func and $lib and $priv and $prov and
         
        // PE Imports + some functions 
		(pe.imports("advapi32.dll","OpenProcessToken")) and
		(pe.imports("advapi32.dll","AdjustTokenPrivileges")) and
        (pe.imports("advapi32.dll","LookupPrivilegeValueA")) and
        (pe.imports("advapi32.dll","OpenSCManagerA")) and
        (pe.imports("advapi32.dll","OpenServiceA")) and
        (pe.imports("advapi32.dll","QueryServiceStatusEx")) and

        //Hash values
		(hash.sha1(0,filesize) == "800978c158cd47da2fdfd1411987bfdf3efa8fb8") and
        (hash.md5(0,filesize) == "e5e04008884303a3304db6d40b89d5f8") and
        (hash.sha256(0,filesize) == "fb23a94633f82c8aa2c251c78f82dd74e665145310ad9de7d439c4b560c4c80d") and

        // File size : ~10k bytes
        filesize <= 143KB and

        // Machine architecture
        (pe.machine == pe.MACHINE_AMD64)
}

