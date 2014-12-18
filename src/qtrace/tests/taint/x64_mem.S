        .global _start
        .text

_start:
.macro TAINTED reg
  xor $0xabadb00b, \reg
.endm

.macro UNTAINTED reg
  xor $0xabadb00c, \reg
.endm

        mov (%rsp), %rax
        xor %rbx, %rbx

        TAINTED %eax
        UNTAINTED %ebx

        mov 8(%rsp), %rbx

        TAINTED %eax
        TAINTED %ebx

        xor %rcx, %rcx
        UNTAINTED %ecx

        mov (%rbx), %cl
        TAINTED %ecx

        xor %rax, %rax
        UNTAINTED %eax

        mov $0x3c, %rax
        mov $0x00, %rdi
        syscall
