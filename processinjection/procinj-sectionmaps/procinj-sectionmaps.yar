import "hash"
import "pe"

rule detect_procinj_sect_maps {
    meta:
		last_updated = "2026-06-04"
		author = "mooolight"
		description = "Yara rule for process injection involving section maps."

	strings:
		$file_type = {4D 5A}
        $WinApi1 = "RtlCreateUserThread" nocase ascii wide
        $WinApi2 = "NtMapViewOfSection" nocase ascii wide
        $WinApi3 = "NtCreateSection" nocase ascii wide
        $WinApi4 = "OpenProcess" nocase ascii wide

	condition:
        // Suspicious strings from Static Analysis phase
        $WinApi1 and $WinApi2 and $WinApi3 and $WinApi4 and $file_type and
        
        // PE Imports + some functions
		(pe.imports("kernel32.dll","OpenProcess")) and
		(pe.imports("ntdll.dll","NtCreateSection")) and
		(pe.imports("ntdll.dll","NtMapViewOfSection")) and
        (pe.imports("ntdll.dll","RtlCreateUserThread")) and

        //Hash values
		(hash.sha1(0,filesize) == "0b282e981241ea6dd1517a6c343bbb323ced4809") and
        (hash.md5(0,filesize) == "e041ff60a117127de7d592c5bde588ac") and
        (hash.sha256(0,filesize) == "2b77bd8b28ee36e9344e93b63a98adf9137bab2cdb1107637c558a0881ec33ff") and

        // File size : ~10k bytes
        filesize >= 142KB and

        // Machine architecture
        (pe.machine == pe.MACHINE_AMD64)
}

