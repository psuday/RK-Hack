#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/types.h>

// In this code we will fix the byte codes that are in the 
// executable of hellosys.c to remove the annoying for loop.
// Once the system call is loaded into the memory, the kernel
// memory bytes have to be patched to fix the call.
// Thus this example program will fix the kernel memory using
// the kernel data access library which is in /lib/libkvm.so

// The size of the hello routine (system call body) is 48 bytes.
// This can be obtained by looking at the objdump output of
// hello.ko. (objdump -dR hellosys.ko)
#define SIZE 0x30

unsigned char nop_code[] = "\x90\x90"; // these are the replacement 
					// codes and are nop
int main(int argc, char ** argv) {
	int i, offset;
	char errbuf[_POSIX2_LINE_MAX];  // An error buffer is needed for the kvm_openfiles call.
	kvm_t *kd;  // pointer to kernel virtual memory
	// The nlist is a struct that holds information about
	 //a symbol such as its name and associated address
	struct nlist nl[] = { {NULL}, {NULL} };

	unsigned char hello_code[SIZE]; // The entire hello routine will
					// be sucked into this array.
	// "Open" the kernel virtual memory: basically get an handle
	// to it.
	// The first three parameters are null: the format for these
	// are in /usr/src/lib/libkvm/kvm.h|c
	// The first one is the name of the kernel image which
	// needs to have a symtab. If NULL the current image is
	// used. The second one is the kernel memory device file.
	// This can point to a core file or if NULL the /dev/mem
	// is used. The third one is not used and it is supposed
	// to point to a swap file.
	// If there is an error that message is written to the
	// buffer pointer passed in as the last argument.
	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
	
	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

	nl[0].n_name = "hello"; // Symbol to search for.

// the kvm_nlist will search the kernel memory for this symbol
// and if found will place the address of the symbol in the
// nl[0].n_value field of the nlist struct.
	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found\n", nl[0].n_name);
		exit(-1);
	}

// Now that we have the address of hello we can read the SIZE bytes
// starting at that address into the array so that we can play
// with it.

	if (kvm_read(kd, nl[0].n_value, hello_code, SIZE) < 0) {
		fprintf(stderr, "ERROR: %s\n ", kvm_geterr(kd));
		exit(-1);
	}

	// Now the sucked in code is examined to figure out where
	// the jmp instruction is located and then replace it with
	// the nop codes.

	for (i = 0; i < SIZE; i++) {
		if (hello_code[i] == 0x75) {
			offset = i;
			break;
		}
	}

// So here the patching is done: starting at the address of hello
// and at the offset of the jmp instruction, the nop_code
// is written for the size of the nop code array.
	if (kvm_write(kd, nl[0].n_value + offset, nop_code,
		sizeof(nop_code) - 1) < 0) {

		fprintf(stderr, "ERROR:%s\n", kvm_geterr(kd));
		exit(-1);
	}

// Finally the memory descriptor is closed.

	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

exit(0);

}

