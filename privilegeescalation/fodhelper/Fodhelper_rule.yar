import "hash"
import "pe"

rule detect_fodhelper{
    meta:
		last_updated = "2026-06-03"
		author = "mooolight"
		description = "Fodhelper - A privilege escalation technique bypassing the UAC mechanism."

	strings:
		$file_type = {4D 5A}
        $bin = "fodhelper.exe" nocase wide ascii
        $binPath  = "C:\\Windows\\System32\\fodhelper.exe" nocase wide ascii
        $cmd = "runas" nocase wide ascii
        $reg = "SOFTWARE\\Classes\\ms-settings\\shell\\open\\command\\" nocase ascii wide
        $cmd2 = "DelegateExecute" nocase ascii wide

	condition:
        // Suspicious strings from Static Analysis phase
        $file_type and $bin and $binPath and $cmd and $reg and $cmd2 and

        // PE Imports + some functions
        (pe.imports("advapi32.dll","RegCreateKeyExA")) and
        (pe.imports("advapi32.dll","RegDeleteKeyExA")) and
        (pe.imports("advapi32.dll","RegSetValueExA")) and
        (pe.imports("advapi32.dll","RegCloseKey")) and
        (pe.imports("shell32.dll","ShellExecuteExA")) and

        //Hash values
		(hash.sha1(0,filesize) == "f35efad3d100cc135070f5e3de3040187be7b300") and
        (hash.md5(0,filesize) == "bca68c694f23c8725e09434c5004e294") and
        (hash.sha256(0,filesize) == "93865832bf88b1284f36b3504df2d90687d9ad30890924bb50e4be72b26141d2") and

        // File size : ~10k bytes
        filesize <= 145KB and

        // Machine Architecture
        (pe.machine == pe.MACHINE_AMD64)
}
