#include <stdio.h>
int main(int argc, char ** argv) {

	int i, baseaddress = 0xc0bb0de0;
	unsigned long offsetarray[] = {
	 0xc0bb0e23 - baseaddress,
	 0xc0bb0e7f - baseaddress,
	 0xc0bb0e9b - baseaddress,
	 0xc0bb0f1e - baseaddress,
	 0xc0bb0f4e - baseaddress,
	 0xc0bb0fc7 - baseaddress,
	 0xc0bb0fe1 - baseaddress,
	 0xc0bb1024 - baseaddress,
	 0xc0bb1080 - baseaddress,
	 0xc0bb1090 - baseaddress,
	 0xc0bb10d3 - baseaddress,
	 0xc0bb10ec - baseaddress,
	 0xc0bb1119 - baseaddress,
	 0xc0bb11d2 - baseaddress,
	 0xc0bb11ff - baseaddress,
	 0xc0bb120f - baseaddress,
	 0xc0bb123a - baseaddress,
	 0xc0bb1292 - baseaddress,
	 0xc0bb12a9 - baseaddress,
	 0xc0bb12ec - baseaddress,
	 0xc0bb134c - baseaddress,
	 0xc0bb1360 - baseaddress,
	 0xc0bb13a3 - baseaddress
};

for (i = 0; i < 23; i++) {
	printf("%x\n", offsetarray[i]);
}

printf("\n");
	
for (i = 3; i < 23; i++) {
	printf("%x\n", offsetarray[i] + 0x7);
}
}
