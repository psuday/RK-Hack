#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <stdlib.h>


// Was trying to figure out the difference between module and syscall.
// I am not entirely clear about this. Can I have a module loaded
// into the kernel and then call it on demand? I think the answer
// is yes. It is like a device driver then. It will be a pseudo
// device driver. The only issue is I am not sure what the interface
// will be like: probably need to study device driver creation
// first.

// Anyway when I call modfind on a non-syscall then of course
// the syscall num will be zero. And I cant use syscall to call it.
int main(int argc, char ** argv) {
	int syscall_num;
	struct module_stat stat;
	
	unsigned long addr;
	
// Straight forward: find the syscall no and call it with
// the size of memory to be allocated: and then the syscall
// allocated memory and returns the address.

	stat.version = sizeof(stat);
	modstat(modfind(argv[1]), &stat);
	syscall_num = stat.data.intval;

	//syscall(syscall_num, (unsigned long)atoi(argv[1]), &addr);

	module_t m = module_lookupbyname("hello");

	printf("System call number is %d\n", syscall_num);

	exit(0);
}
