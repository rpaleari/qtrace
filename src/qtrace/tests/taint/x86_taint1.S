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

	TAINTED %eax
	UNTAINTED %ebx

	mov 4(%esp), %ebx
	
	TAINTED %eax
	TAINTED %ebx

	xor %ecx, %ecx
	UNTAINTED %ecx

	mov (%ebx), %cl
	TAINTED %ecx

	xor %eax, %eax
	UNTAINTED %eax

	inc %eax
	int $0x80
