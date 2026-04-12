/*
 * 10_api_hashing.c
 * ==================
 * API Hashing - Resolves functions at runtime without exposing names in the binary
 *
 * When you use GetProcAddress("VirtualAlloc") or import functions
 * normally, the name "VirtualAlloc" appears as a string in the binary.
 * Any analyst with "strings malware.exe" can see which APIs you use.
 *
 * API Hashing solves this: instead of storing the name, we store
 * a HASH of the name (a number). At runtime, we iterate through all
 * exported functions of a DLL, calculate the hash of each name,
 * and compare. If it matches, we found the function.
 *
 * Zero suspicious strings in the binary.
 *
 * This example uses the djb2 algorithm (Daniel J. Bernstein) - simple
 * and effective. Other common ones: CRC32, ROR13, FNV-1a.
 *
 * Compile: cl.exe /O2 10_api_hashing.c
 */

#include <windows.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * hashDJB2 - Calculates the hash of a string using the djb2 algorithm
 *
 * djb2 is one of the simplest hash algorithms for strings.
 * Formula: hash = hash * 33 + character
 *
 * Starts with a "magic number" 5381 (empirically chosen
 * by Bernstein for good distribution).
 *
 * The << 5 operator is a multiplication by 32 (left shift by 5 bits).
 * So (hash << 5) + hash = hash * 32 + hash = hash * 33.
 *
 * Collisions are rare for Windows function names.
 *
 * Parameters:
 *   str -> function name (e.g.: "VirtualAlloc")
 *
 * Returns: 32-bit hash (e.g.: 0x91AFCA54)
 * --------------------------------------------------------------- */
DWORD hashDJB2(const char* str) {
    DWORD hash = 5381;     /* initial value (djb2 magic number) */
    int c;

    while ((c = *str++)) {
        /*
         * For each character:
         *   hash = hash * 33 + c
         *
         * Bitshift version (faster):
         *   (hash << 5) = hash * 32
         *   (hash << 5) + hash = hash * 33
         */
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}


/* ---------------------------------------------------------------
 * resolveFunctionByHash - Finds a function in a DLL by its hash
 *
 * This function manually does what GetProcAddress does, but
 * compares hashes instead of names.
 *
 * The process is:
 *   1. Get the base address of the DLL in memory
 *   2. Parse the PE header to find the export table
 *   3. Iterate through all exported names
 *   4. For each name, calculate the djb2 hash
 *   5. If the hash matches, return the function address
 *
 * Parameters:
 *   hModule    -> handle/base address of the DLL (e.g.: kernel32.dll)
 *   targetHash -> hash of the function we want (pre-calculated)
 *
 * Returns: pointer to the function, or NULL if not found
 * --------------------------------------------------------------- */
LPVOID resolveFunctionByHash(HMODULE hModule, DWORD targetHash) {

    /*
     * The base address of the DLL is where the PE starts in memory.
     * Cast to BYTE* to be able to do byte-by-byte pointer arithmetic.
     */
    BYTE* base = (BYTE*)hModule;

    /* ---------------------------------------------------------------
     * Parse PE Headers
     *
     * Every PE starts with a DOS Header (64 bytes).
     * dosHeader->e_lfanew points to the NT Header.
     * ntHeaders->OptionalHeader.DataDirectory[0] = Export Directory
     * --------------------------------------------------------------- */
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

    /*
     * Export Directory contains:
     *   - NumberOfNames: how many functions are exported by name
     *   - AddressOfNames: array of RVAs (offsets) to the names
     *   - AddressOfFunctions: array of RVAs to the function addresses
     *   - AddressOfNameOrdinals: maps name index to function index
     *
     * RVA = Relative Virtual Address = offset from the DLL base
     * To convert RVA to pointer: base + RVA
     */
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);

    /* Arrays of names, functions and ordinals */
    DWORD* names     = (DWORD*)(base + exportDir->AddressOfNames);
    DWORD* functions = (DWORD*)(base + exportDir->AddressOfFunctions);
    WORD*  ordinals  = (WORD*)(base + exportDir->AddressOfNameOrdinals);

    /* Iterate through all exported functions */
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {

        /* current function name (RVA -> pointer) */
        const char* funcName = (const char*)(base + names[i]);

        /* Calculate hash of the name */
        DWORD currentHash = hashDJB2(funcName);

        /* If it matches the hash we're looking for, we found it! */
        if (currentHash == targetHash) {
            /*
             * ordinals[i] maps the name index to the function index.
             * functions[ordinal] contains the RVA of the function.
             * base + RVA = actual address of the function in memory.
             */
            WORD ordinal = ordinals[i];
            LPVOID functionAddress = (LPVOID)(base + functions[ordinal]);
            return functionAddress;
        }
    }

    return NULL; /* not found */
}


int main() {

    printf("[*] API Hashing with djb2\n");
    printf("[*] =====================\n\n");

    /* ---------------------------------------------------------------
     * Pre-calculate hashes of the functions we'll need.
     *
     * In production, you would calculate these at compile time
     * and use them directly as constants (0x91AFCA54, etc).
     * No function name would appear in the binary.
     *
     * Here we calculate at runtime for educational purposes.
     * --------------------------------------------------------------- */
    printf("[*] Calculating function hashes...\n");

    /* We'll resolve these functions without using their names as fixed strings */
    const char* testFunctions[] = {
        "VirtualAlloc",
        "VirtualProtect",
        "CreateThread",
        "VirtualFree",
    };

    for (int i = 0; i < 4; i++) {
        DWORD hash = hashDJB2(testFunctions[i]);
        printf("    %s -> 0x%08X\n", testFunctions[i], hash);
    }

    /* ---------------------------------------------------------------
     * Now resolve functions ONLY by hash (without names)
     *
     * In production, the code would only have:
     *   resolveFunctionByHash(hKernel32, 0x91AFCA54)
     * Without any "VirtualAlloc" string in the binary.
     * --------------------------------------------------------------- */
    printf("\n[*] Resolving functions by hash...\n");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

    /* Resolve VirtualAlloc by hash */
    DWORD hashVirtualAlloc = hashDJB2("VirtualAlloc");
    LPVOID pVirtualAlloc = resolveFunctionByHash(hKernel32, hashVirtualAlloc);

    if (pVirtualAlloc) {
        printf("[+] Hash 0x%08X resolved to: 0x%p\n", hashVirtualAlloc, pVirtualAlloc);

        /* Verify it matches GetProcAddress (for confirmation) */
        LPVOID pOriginal = (LPVOID)GetProcAddress(hKernel32, "VirtualAlloc");
        printf("    GetProcAddress returns: 0x%p\n", pOriginal);
        printf("    Match: %s\n", (pVirtualAlloc == pOriginal) ? "YES" : "NO");
    }

    /* Resolve VirtualProtect */
    DWORD hashVirtualProtect = hashDJB2("VirtualProtect");
    LPVOID pVirtualProtect = resolveFunctionByHash(hKernel32, hashVirtualProtect);

    if (pVirtualProtect) {
        printf("[+] Hash 0x%08X resolved to: 0x%p\n", hashVirtualProtect, pVirtualProtect);
    }

    /* ---------------------------------------------------------------
     * Use the resolved functions
     *
     * To call the resolved function, we cast to the correct type.
     *
     * typedef defines the "format" of the function:
     *   - return type (LPVOID)
     *   - calling convention (WINAPI)
     *   - parameters (LPVOID, SIZE_T, DWORD, DWORD)
     *
     * The cast (fnVirtualAlloc)pVirtualAlloc transforms the generic
     * pointer into a function pointer we can call.
     * --------------------------------------------------------------- */
    printf("\n[*] Using resolved function to allocate memory...\n");

    typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

    fnVirtualAlloc myVirtualAlloc = (fnVirtualAlloc)pVirtualAlloc;

    /* Call VirtualAlloc without ever having written "VirtualAlloc" as an import */
    LPVOID mem = myVirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (mem) {
        printf("[+] Memory allocated at: 0x%p\n", mem);
        printf("[+] No API strings appear in the binary!\n");

        /* Cleanup */
        typedef BOOL (WINAPI* fnVirtualFree)(LPVOID, SIZE_T, DWORD);
        DWORD hashVirtualFree = hashDJB2("VirtualFree");
        fnVirtualFree myVirtualFree = (fnVirtualFree)resolveFunctionByHash(hKernel32, hashVirtualFree);
        if (myVirtualFree) myVirtualFree(mem, 0, MEM_RELEASE);
    }

    return 0;
}
