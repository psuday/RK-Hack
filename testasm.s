# This assembler segment is needed to figure out the patch that 
# I need to apply to the syscall code.
.section .text
.globl _start
_start:
	nop
	movl $0xc3954000, 0x4(%eax)
	movl $1, %eax
	int $0x80
