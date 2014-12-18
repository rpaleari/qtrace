	// Tests for bitwise operations

	.global _start
	.text

_start:
.macro TAINTED reg
  xor $0xabadb00b, \reg
.endm

.macro UNTAINTED reg
  xor $0xabadb00c, \reg
.endm

.macro CHECK
 TAINTED %eax
 TAINTED %ebx
 xor %rbx, %rbx
 TAINTED %eax
 UNTAINTED %ebx
.endm

	mov (%rsp), %rax
	xor %rbx, %rbx
	TAINTED %eax
	UNTAINTED %ebx

	// and_i64 tmp0,tmp0,tmp1
	and %eax, %ebx
	CHECK

	// or_i64 tmp0,tmp0,tmp1
	or %eax, %ebx
	CHECK

	mov $0x3c, %rax
	mov $0x00, %rdi
	syscall
