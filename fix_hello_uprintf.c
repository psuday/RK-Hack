// This code patches the for loop as in fix_hello
// and in addition also patches the printf call
// to replace it with a uprintf call. 
// But better still is to replace this with some other
// custom message also.

//  The point to note here is that the uprintf, printf,
// etc are located in the kernel memory at a certain address
// and all call sites will link to this address
// call <printf_address>

// First a little address manipulation - not the uprintf 
// So in kong's code he patches the printf and makes it 
// uprintf. I did a little modification and now I
// substitute the string output by printf.
// 
// 

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
#define SIZE 0x50

// Two arrays are here: one for the patching of the print string
// and the other for patching the for loop. These could easily
// have been a single array also. But it is easier this way and
// more clean.

// Now in the print code below the bytes placed in are the 
//address for the substitution string. This cannot be obtained
// by just doing a objdump of hellosys.ko because those addresses
// are relative addresses. Instead we have to dump the kernel 
// memory first using this program (the hello_code array) and
// then examine that to find the real address of the string.
// This can be done by doing objdump first and the comparing that
// output with the contents of the hello_code array. The offsets
// are the same only the addresses are different. Once the address
// bytes are figured out they can be substituted for the
// values below and stored in the array.
// For patching the for loop there is no such problem because
// we just want to replace with nop codes. Likewise there is no
// problem for replacing an op code (for example printf with uprintf)
// because those are absolute addresses which can be obtained by
// kvm_list (uprintf is a symbol in the symtab of the kernel.
// Only data addresses need the above treatment.
unsigned char print_code[] = "\xe4\xa5"; // these are the replacement 
unsigned char jmp_code[] = "\x90\x90"; // these are the replacement 
					// codes and are nop
int main(int argc, char ** argv) {
	int i, jmp_offset, printstring_offset, callflag = 0;
	char errbuf[_POSIX2_LINE_MAX];  // An error buffer is needed for the kvm_openfiles call.
	kvm_t *kd;  // pointer to kernel virtual memory
	// The nlist is a struct that holds information about
	 //a symbol such as its name and associated address
	struct nlist nl[] = { {NULL}, {NULL} ,{NULL}, };

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
	// the nop codes. The first loop is for the print string
	// and the second loop is for the for loop offset calculation.

	for (i = 0; i < SIZE; i++) {
		if (hello_code[i] == 0xc7) {
				callflag++;
				if (callflag == 3) {
					printstring_offset = i + 4 ;
					break;
				}
		} 
	}

	for (i = 0; i < SIZE; i++) {
		if (hello_code[i] == 0x75) {

			jmp_offset = i;
			break;
		}
	}



// So here the patching is done: starting at the address of hello
// and at the offset of the jmp instruction, the nop_code
// is written for the size of the nop code array.

	if (kvm_write(kd, nl[0].n_value + printstring_offset, print_code,
		sizeof(print_code) - 1) < 0) {

		fprintf(stderr, "ERROR:%s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_write(kd, nl[0].n_value + jmp_offset, jmp_code,
		sizeof(jmp_code) - 1) < 0) {

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


