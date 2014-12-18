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

        // Check taintedness is PRESERVED when pushing/popping registers
        TAINTED %eax
        UNTAINTED %ebx

        push %rax
        pop %rbx

        TAINTED %eax
        TAINTED %ebx

        // Check taintedness is CLEARED when pushing/popping registers
        xor %rcx, %rcx
        TAINTED %eax
        UNTAINTED %ecx

        push %rcx
        pop %rax

        UNTAINTED %eax
        UNTAINTED %ecx

        // Check taintedness is PRESERVED when moving to/from memory
        UNTAINTED %eax
        TAINTED %ebx
        UNTAINTED %ecx

        mov %rbx, 0x8(%rsp)
        mov 0x8(%rsp), %rax

        TAINTED %eax
        TAINTED %ebx

        // Check taintedness is CLEARED when moving to/from memory
        TAINTED %eax
        TAINTED %ebx
        UNTAINTED %ecx

        mov %rcx, 0x8(%rsp)
        mov 0x8(%rsp), %rax

        UNTAINTED %eax
        TAINTED %ebx
        UNTAINTED %ecx

        mov $0x3c, %rax
        mov $0x00, %rdi
        syscall
