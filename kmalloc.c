// This code will allocate kernel memory. So there will as usual
// be a system call which on invocation will allocate memory
// and return back the address. Very dangerous and to be used
// caution. 
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>

// One input parameter and one output parameter. We already did
// this earlier in sc_example.c program. The second parameter
// is the output containing the address of the allocated memory.
struct kmalloc_args {
	unsigned long size;
	unsigned long * address;
};

static int kmalloc (struct thread * td, void * syscall_args) {
	struct kmalloc_args * uap;
	uap = (struct kmalloc_args *)syscall_args;

	int error; 
	unsigned long addr;

	// The macro below encapsulates the call to malloc.
	// The first paramter is the pointer variable to which
// the memory address is assigned. The second paramter is the cast
// of the raw memory allocated by malloc into the appropriate type.
// The remaining three parameters are passed to the malloc syscall.
// The size, the type specified a struct pointer which can
// collect the statistics on mem usage etc. M_TEMP means that 
// that it is a misc temp buffer.  And the final one is 
// a set of flags that can be specified to malloc for things 
// like zero initialization etc.
// 
	MALLOC(addr, unsigned long, uap->size, M_TEMP, M_NOWAIT);

	error = copyout(&addr, uap->address, sizeof(addr));

	return error;
}


static struct sysent kmalloc_sysent = {
	2,
	kmalloc
};

static int offset = NO_SYSCALL;

static int load(struct module * module, int cmd, void * arg) {
	int error = 0;
	
	switch(cmd) {
		case MOD_LOAD:
			uprintf("System call loaded at %d\n", offset);
			break;
		case MOD_UNLOAD:
			uprintf("System call unloaded \n"); 
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return error;
}

SYSCALL_MODULE(kmalloc, &offset, &kmalloc_sysent, load, NULL);

	

