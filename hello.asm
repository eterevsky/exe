EXTERN GetStdHandle : PROC
EXTERN WriteFile : PROC
EXTERN ExitProcess : PROC

.code

mainCRTStartup PROC
_start:
    sub rsp, 38h
    mov dword ptr [rsp + 34h], 0

    ; Get handle to standard output
    mov ecx, -11                    ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [rsp + 28h], rax            ; Store handle

    ; Write message to standard output
    mov rcx, [rsp + 28h]            ; Handle
    lea rdx, message                ; Message
    mov r8d, 14
    lea r9, [rsp + 34h]
    mov qword ptr [rsp + 20h], 0
    call WriteFile

    ; Exit process
    xor ecx, ecx                    ; Exit code = 0
    call ExitProcess
mainCRTStartup ENDP

    message db 'Hello, World!', 0

END
