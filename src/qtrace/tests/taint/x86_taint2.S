        .global _start
        .text

_start:
.macro TAINTED reg
  xor $0xabadb00b, \reg
.endm

.macro UNTAINTED reg
  xor $0xabadb00c, \reg
.endm

        mov (%esp), %eax
        xor %ebx, %ebx

        // Check taintedness is PRESERVED when pushing/popping registers
        TAINTED %eax
        UNTAINTED %ebx

        push %eax
        pop %ebx

        TAINTED %eax
        TAINTED %ebx

        // Check taintedness is CLEARED when pushing/popping registers
        xor %ecx, %ecx
        TAINTED %eax
        UNTAINTED %ecx

        push %ecx
        pop %eax

        UNTAINTED %eax
        UNTAINTED %ecx

        // Check taintedness is PRESERVED when moving to/from memory
        UNTAINTED %eax
        TAINTED %ebx
        UNTAINTED %ecx

        mov %ebx, 0x4(%esp)
        mov 0x4(%esp), %eax

        TAINTED %eax
        TAINTED %ebx

        // Check taintedness is CLEARED when moving to/from memory
        TAINTED %eax
        TAINTED %ebx
        UNTAINTED %ecx

        mov %ecx, 0x4(%esp)
        mov 0x4(%esp), %eax

        UNTAINTED %eax
        TAINTED %ebx
        UNTAINTED %ecx

        xor %eax, %eax
        inc %eax
        int $0x80
