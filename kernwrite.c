// ok, this routine is even more dangerous because it will just scribble
// something over a kernel address.
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


//unsigned char jump[] = "\xb8\x00\x50\x49\xc3\xff\xe0";
unsigned char jump[] = "\x01\x00\x00";
int main(int argc, char ** argv) {
	
	char errbuf[_POSIX2_LINE_MAX];

	kvm_t *kd;


	unsigned long addr = strtoll(argv[1], NULL, 16);

	printf("Scribbling over address 0x%x\n", addr);


	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

	if (kvm_write(kd, addr , jump, 1) < 0 ) { 
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	exit(0);
}


	


