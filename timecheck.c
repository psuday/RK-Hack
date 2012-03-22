// This program snippet will help ease my insanity
// and also help do a check on the different time fields
// in the stat struct.
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
// The stdlib include is needed for the exit function. Otherwise the 
// prototype is mising and gcc will issue warnings.
#include <stdlib.h>

int main(int argc, char  ** argv) {
	
	struct stat sb;

	struct timeval time[2];

	if (stat("/home/rootkit", &sb) < 0) {
		fprintf(stderr, "STAT ERROR: %d\n", errno);
		exit(-1);
	}
	
	printf("Time of last change is %d\n", sb.st_atime);
}
