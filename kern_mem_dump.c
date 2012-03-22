#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>

#define SIZE 200
int main(int argc, char ** argv) {
	int i ;
	char errbuf[_POSIX2_LINE_MAX];  // An error buffer is needed for the kvm_openfiles call.
	kvm_t *kd;  // pointer to kernel virtual memory
	// The nlist is a struct that holds information about
	 //a symbol such as its name and associated address

	unsigned char mem[SIZE]; 

	int size = atoi(argv[1]);

	unsigned long addr = (unsigned long)strtoll(argv[2], (char **)NULL, 16);
	
	//printf("Error is %d\n" , errno);

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
	
	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}


	if (kvm_read(kd, addr, mem, size) < 0) {
		fprintf(stderr, "ERROR: %s\n ", kvm_geterr(kd));
		exit(-1);
	}


	for (i = 0; i < size; i++) {
		printf("0x%x\n ", mem[i]);
	}

	printf("\n");


	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}


	return 0;
}

