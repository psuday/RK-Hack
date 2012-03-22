// This is a hook in the mi_switch context switch routine which is
// in /usr/src/sys/kern and it implements the machine independent
// parts of the context switching. 

// So what is the pseudo code?
// First we need to have a hook inline in the mi_switch code
// which will essentially use the curthread data structure
// for the process related info. The intent is to print out
// the process id.

// After getting the curthread struct's address, an unconditional
// jmp has to be inserted into the mi_switch code. This will
// point to a chunk of newly allocated kernel memory. That new
// chunk of memory will contain code to do the following:
// a) Extract pid from the curthread struct
// b) Save register state prior to printf call
// c) Setup state for printf call
// d) Call printf
// e) Restore register and stack state after printf
// f) Execute code that got clobbered by the jmp statement in mi_switch
// g) Jump back to the point after the jmp statement in mi_switch.
// h) Pray.
// 

// So here what is happening is that we are going to patch
// the mkdir code again: but now we want to jmp to our shell
// code from the mkdir code and then jmp back again as if nothing
// has happened. 
// We need this because sometimes our shellcode will be big in size
// and it may not fit into the confines of an existing syscall code. 
// So we need to patch the existing syscall (mi_switch) with a jmp
// instruction and then append the syscall code overwritten by
// the jmp to the shellcode.
// and then we add the jmp back to the syscall code after that
// It is a tedious bit of coding. 

#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <stdlib.h>

// This shellcode is for extracting the current proc id from
// the curthread variable and then printing it using a printf
// call. Then stack adjustment is done.  The bytecodes are
// obtained by doing a objdump -d on mi_switchmodule.o. This
// module had to be written so that I could compile it and
// then run a objdump on the .o file.
// The code is in mi_switchmodule.c in the miswitchhook function

// In that function decompile: 
// the call to printf is set up as follows:
// sub $0x8, %esp
// movl $0x0, (%esp)
// movl %eax, 0x4(%esp)
// call ....

// So the two movl are for the format string and for the
// current procid (whic is in eax register).
// The format string is in the .rodata section of the disassembled
// code. We need to patch this address in the shellcode below.
// So first the .rodata values (objdump will disassemble this also
// as code and display on the rhs. But this is really data. Each hex
// value represents the ascii value of the format string
// "Current proc id is %d\n") are copied to the start of the shellcode
// array. Then the movl $0x0, (%esp) is patched to replace 0x0
// with the kernel address to which this shellcode is copied.

// 
unsigned char shellcode[] = 
	"\x43"
	"\x75\x72"
	"\x72\x65"
	"\x6e"
	"\x74\x20"
	"\x70\x72"
	"\x6f"
	"\x63\x20"
	"\x69\x64\x20\x69\x73\x20\x25"
	"\x64"
	"\x0a\x00"
	"\x64\xa1\x00\x00\x00\x00"
	"\x83\xec\x08"
	"\x8b\x40\x04"
	"\x8b\x40\x64"
	"\xc7\x04\x24\x00\x00\x00\x00"
	"\x89\x44\x24\x04"
	"\xe8\xfc\xff\xff\xff"
	"\x83\xc4\x08";

// This offset is for the byte immediately following the printf call.
// We count this from the start of the shellcode array. And it is the
// number of steps till we reach the end of the call (the last \xff in 
// \xe8 row). 

#define H_OFFSET_1 0x36

// Unconditional jump code, will be patched twice.

unsigned char jump[] = "\xb8\x00\x00\x00\x00"
			"\xff\xe0";

int main(int argc, char ** argv) {
	
	int i, call_offset , syscall_num;

	struct module_stat stat ;

	char errbuf[_POSIX2_LINE_MAX];

	kvm_t *kd;

	struct nlist nl[] = { {NULL}, {NULL}, {NULL}};

	unsigned char miswitch_code[100];

	unsigned long addr = 0, addr1 = 0, size;

	stat.version = sizeof(stat) ;
	modstat(modfind("kmalloc"), &stat);

	syscall_num = stat.data.intval;

	syscall(syscall_num, 100, &addr1);

	// This address addr1 is where we will store the original
	// version of the mi_switch code. This will be used
	// by the uninstall routine.

	printf("Address 1 is %0x \n", addr1);

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

	nl[0].n_name = "printf";
	nl[1].n_name = "mi_switch";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found \n");
		exit(-1);
	}

	if (kvm_read(kd, nl[1].n_value, miswitch_code, 100) < 0 ) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	// We want to copy the start of the mi_switch code
	// into the array.
	// We pick a point somewhere near the start (the point
	// is defined by the 0x64 bytecode.

	for (i = 0; i < 100 ; i++) {
		if (miswitch_code[i] == 0x64) {
			call_offset = i;
			break;
		}
	}

	size = (unsigned long)sizeof(shellcode) + (unsigned long)call_offset +
		(unsigned long)sizeof(jump);

// This memory allocation is for copying the shellcode and the starting
// few bytes of mi_switch and the jmp code.

	syscall(syscall_num, size, &addr);

	printf("Call offset for kern_mkdir is %d\n", call_offset);

// The two patches below are for a) The first movl for the format string
// of the printf call and b) for the address of the printf call.

	*(unsigned long *)&shellcode[41] = addr;
	*(unsigned long *)&shellcode[50] = nl[0].n_value - (addr + H_OFFSET_1);

// Write shellcode

	if (kvm_write(kd, addr, shellcode, sizeof(shellcode)) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

// Copy mi_switch to addr1 for later restore in uninstall routine.

	if (kvm_write(kd, addr1, miswitch_code, sizeof(miswitch_code)) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

// Now write the first few bytes of mi_switch after the shellcode.

	if (kvm_write(kd, addr + (unsigned long)sizeof(shellcode) - 1,
		miswitch_code, call_offset) < 0) {
			fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
			exit(-1);
	}

// First patch of jump to jump back to the point in mi_switch after the
// initial bytes that were copied to the shellcode.

	*(unsigned long *)&jump[1] = nl[1].n_value + (unsigned long)call_offset;

// Write the patched jump code after the mi_switch code.

	if (kvm_write(kd, addr + (unsigned long)sizeof(shellcode) - 1 +
		(unsigned long)call_offset, jump, sizeof(jump)) < 0) {
			fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
			exit(-1);
	}

// Second patch of jump to jump to the part of the shellcode after
// the initial data string. Data doesnt execute, ha ha.

	*(unsigned long *)&jump[1] = addr + 0x17;

// now write that jump code to the start of the mi_switch code.

	if (kvm_write(kd, nl[1].n_value , jump, sizeof(jump)) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}


	exit(0);
}


	


