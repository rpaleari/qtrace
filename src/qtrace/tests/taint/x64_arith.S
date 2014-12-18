	// Tests for arithmetic operations

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

	// add_i64 tmp0,tmp0,tmp1
	// ext32u_i64 rbx,tmp0
	add %eax, %ebx
	CHECK

	add $0xcafebabe, %ebx
	TAINTED %eax
	UNTAINTED %ebx	

	// sub_i64 tmp0,tmp0,tmp1
	// ext32u_i64 rbx,tmp0
	sub %eax, %ebx
	CHECK

	sub $0x1, %ebx
	TAINTED %eax
	UNTAINTED %ebx

	// Check that "sub T, T" clears the taint status of register T
	mov %eax, %ebx
	TAINTED %ebx
	sub %ebx, %ebx
	UNTAINTED %ebx

	mov %rax, %rbx
	TAINTED %ebx
	sub %rbx, %rbx
	UNTAINTED %ebx

	mov $0x3c, %rax
	mov $0x00, %rdi
	syscall
