// This routine will "uninstall" the mi_switchhook.

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

int main(int argc, char ** argv) {
	
// This is an user land program. 
	char errbuf[_POSIX2_LINE_MAX];

	kvm_t *kd;

	struct nlist nl[] = { {NULL}, {NULL}, {NULL}};

// We need this array because we cant directly transfer data from 
// one kernel address to the other using kvm_read and write.

	unsigned char miswitchcode[100];

// This is the memory address at which the original miswitchcode
// is stored.

	unsigned long addr = 0;

// We pass in that address (which is displayed by the miswitchhook routine
// to this routine as a commandline parameter
	addr = (unsigned long)strtoll(argv[1], (char **)NULL, 16);


	printf("%x\n", addr);

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

	nl[0].n_name = "mi_switch";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

// At this point we have the kernel address of the mi_switch routine
// which has been patched by the earlier mi_switchhook routine.
	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found \n");
		exit(-1);
	}

// Now we read the original code which is stored at kernel address addr
// to the userland memory at miswitchcode.

	if (kvm_read(kd, addr, miswitchcode, 100) < 0 ) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

// Now we perform the write to the mi_switch code of the original
// code, thereby effectively "uninstalling" the patch.

	if (kvm_write(kd, nl[0].n_value, miswitchcode, 100) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}


	exit(0);
}


	


