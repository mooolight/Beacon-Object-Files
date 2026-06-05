import "hash"
import "pe"

rule detect_eppblkfw {
    meta:
		last_updated = "2026-06-04"
		author = "mooolight"
		description = "Yara rule for blocking Endpoint Protection network connection using a firewall rule."

	strings:
		$file_type = {4D 5A}
        $eppBinPath = "C:\\Program Files\\Bitdefender Antivirus Free\\vsserv.exe" nocase ascii wide        
        $ruleDesc = "Deny malicious outbound network traffic" nocase ascii wide
        $lib = "ole32.dll" nocase ascii wide
        $prot = "Windows Defender Firewall Remote Management (RPC)" nocase ascii wide

	condition:
        // Suspicious strings from Static Analysis phase
        $eppBinPath and $file_type and $ruleDesc and $prot and $lib and
         
        // PE Imports + some functions 
		(pe.imports("ole32.dll","CoCreateInstance")) and
		(pe.imports("ole32.dll","CoInitializeEx")) and
        (pe.imports("ole32.dll","CoUninitialize")) and
        (pe.imports("ole32.dll","CoSetProxyBlanket")) and

        //Hash values
		(hash.sha1(0,filesize) == "2a9c3a19c6fd6397012b98fd6c78713cd4bde73f") and
        (hash.md5(0,filesize) == "87d168e2f7794c2cc8abbf89da602a1d") and
        (hash.sha256(0,filesize) == "408cc8281ae66a9efe0ea49d8b36211a4316da3c449f43bbd12d2c8f9f3b6731") and

        // File size : ~10k bytes
        filesize <= 141KB and

        // Machine architecture
        (pe.machine == pe.MACHINE_AMD64)
}

