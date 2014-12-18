	// Various tests to stress "deposit" micro-ops

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
 UNTAINTED %ebx
.endm

	mov (%rsp), %rax
	xor %rbx, %rbx
	TAINTED %eax
	UNTAINTED %ebx

	// deposit_i64 rbx,rbx,tmp0,$0x8,$0x8
	mov %al, %bh
	CHECK

	// deposit_i64 rbx,rbx,tmp0,$0x0,$0x8
	mov %al, %bl
	CHECK

	// deposit_i64 rbx,rbx,tmp0,$0x0,$0x10
	mov %ax, %bx
	CHECK

	mov $0x3c, %rax
	mov $0x00, %rdi
	syscall
