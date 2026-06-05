import "hash"
import "pe"

rule detect_pers_runkeys {
    meta:
		last_updated = "2026-06-04"
		author = "mooolight"
		description = "Yara rule for embedding persistence in the compromised system."

	strings:
		$file_type = {4D 5A}
        $registry1 = "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\" nocase ascii wide
        $registry2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide
        $lib = "ADVAPI32.dll" nocase ascii wide

	condition:
        // Suspicious strings from Static Analysis phase
        $registry1 and $registry2 and $file_type and $lib and
        
        // PE Imports + some functions
		(pe.imports("advapi32.dll","RegCloseKey")) and
		(pe.imports("advapi32.dll","RegOpenKeyExA")) and
        (pe.imports("advapi32.dll","RegSetValueExA")) and

        //Hash values
		(hash.sha1(0,filesize) == "a3c20976f292539dfd94f64fb0ffea4d25d13c5a") and
        (hash.md5(0,filesize) == "dbd73cf5907fa3ec8d9ac9b2e14a2975") and
        (hash.sha256(0,filesize) == "4ea9126794b956463c64b43cce8a8984f92cb374d2fddd21f6e48d1b589cac7c") and

        // File size : ~10k bytes
        filesize >= 140KB and

        // Machine architecture
        (pe.machine == pe.MACHINE_AMD64)
}

