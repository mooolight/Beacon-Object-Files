import "hash"
import "pe"

rule detect_ransomexec {
    meta:
		last_updated = "2026-06-04"
		author = "mooolight"
		description = "Yara rule for blocking ransomware simulation executable."

	strings:
		$file_type = {4D 5A}     
        $enc = ".AES" nocase ascii wide    
        $rsa = "Microsoft Enhanced RSA and AES Cryptographic Provider" nocase ascii wide    
        $lib = "ADVAPI32.dll" nocase ascii wide 
        $ransomSuffix = ".decrypted" nocase ascii wide   

	condition:
        // Suspicious strings from Static Analysis phase
        $file_type and $enc and $rsa and $lib and $ransomSuffix and
         
        // PE Imports + some functions 
		(pe.imports("advapi32.dll","CryptDestroyKey")) and
		(pe.imports("advapi32.dll","CryptAcquireContextA")) and
        (pe.imports("advapi32.dll","CryptReleaseContext")) and
        (pe.imports("advapi32.dll","CryptCreateHash")) and
        (pe.imports("advapi32.dll","CryptHashData")) and
        (pe.imports("advapi32.dll","CryptDeriveKey")) and
        (pe.imports("advapi32.dll","CryptEncrypt")) and
        (pe.imports("advapi32.dll","CryptDecrypt")) and

        //Hash values
		(hash.sha1(0,filesize) == "516bc54d0cdf3662d7453e1d0407b1d0afa1ab6b") and
        (hash.md5(0,filesize) == "bbfa1b5b142a67cf09f8ee5288b57339") and
        (hash.sha256(0,filesize) == "948463a70d7562ce7321798b4296658f9aabae86bcedb10a519af9a19df88356") and

        // File size : ~10k bytes
        filesize <= 114KB and

        // Machine architecture
        (pe.machine == pe.MACHINE_AMD64)
}

