; Copyright 2014, Roberto Paleari (@rpaleari)
        
.686p
.model flat,StdCall
option casemap:none
extern KiFastSystemCall:DWORD
.CODE

; First version, with a local backup copy of syscall arguments
DoSyscall1 PROC StdCall _sysno, _nargs, _args
        xor ecx, ecx

saveargs:
        mov eax, [_args+ecx*4]
        push [eax]
        inc ecx
        cmp ecx, _nargs
        jne saveargs
        
        mov eax, _sysno
        push 0CAFEBABEh
        
        call [KiFastSystemCall]

        ret
DoSyscall1 ENDP

; Second version, with no local backup copies. This function assumes register
; ebx is preserved by KiFastSystemCall invocation
DoSyscall PROC StdCall _sysno, _args
        mov eax, _args
        sub eax, 4

        ; Overwritten by the "call" return address
        push [eax-4]
        push eax
        mov ebx, esp
        
        mov esp, eax
        mov eax, _sysno
        call [KiFastSystemCall]

        ; Don't touch eax, as it contains the syscall return value
        mov esp, ebx
        pop ebx
        pop [ebx-4]        
        
        ret
DoSyscall ENDP


END
