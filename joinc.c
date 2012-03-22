#include <stdio.h>

int main(int argc, char** argv) {

	FILE * f1 = fopen(argv[1], "r");
	FILE * f2 = fopen(argv[2], "r");

	FILE * f3 = fopen(argv[3], "w");
	 int count = 0;
	
	char buf[80];
	char buf1[80];

	while (fgets(buf, 80, f1) && fgets(buf1, 80, f2)) {
		printf("%s%s\n",  buf, buf1);
		
	}


}
