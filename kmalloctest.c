#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>

int main(int argc, char ** argv) {
	int syscall_num;
	struct module_stat stat;
	
	unsigned long addr;
	
// Straight forward: find the syscall no and call it with
// the size of memory to be allocated: and then the syscall
// allocated memory and returns the address.

	stat.version = sizeof(stat);
	modstat(modfind("kmalloc"), &stat);
	syscall_num = stat.data.intval;

	syscall(syscall_num, (unsigned long)atoi(argv[1]), &addr);

	printf("Address of allocated kernel memory: 0x%x\n", addr);

	exit(0);
}
