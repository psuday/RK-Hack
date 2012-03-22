//This routine will be a system call that will tamper with the
// addresses in the sysent table. This was written to test the
// Trojan sysent table. After creating the trojan through the copysysent
// program: this program was run to mess up the function pointers in 
// the old sysent table. If the trojan operation was successful then
// this tampering of function pointers in the old table will leave
// the system unscathed. It did.

// This syscall takes three parameters: two addresses and one index value.
// The first address is that of the sysent table and the second address
// is the bogus function pointer and the index value is that into the
// sysent table (at address 1).

// I am wondering now: I should have written this as a KLM and not
// a syscall. Because syscalls have to be inserted into the sysent
// table and that is what we are experimenting with. Not that it is 
// a great problem, but it would have been cleaner that way.
// The reason for writing this as a system call was only to access
// kernel memory. A KLM can do that also.

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

struct sysentreplace_args {

	unsigned long address;
	unsigned long address1;
	int index;
};

static int sysentreplace(struct thread * td, void * syscall_args) {

	struct sysentreplace_args *uap = (struct sysentreplace_args *)syscall_args;
	struct sysent *s = (struct sysent *)uap->address;
	
	s[uap->index].sy_call = (sy_call_t *)uap->address1;
	
	return 0;

}

static struct sysent sysentreplace_sysent = {
	3,
	sysentreplace
};
static int offset = NO_SYSCALL;
static int load(struct module* module, int cmd, void * arg) {

	int error = 0;

	switch(cmd) {
		case MOD_LOAD:
			uprintf("Sys call loaded at %d\n", offset);
			break;
		case MOD_UNLOAD:
			uprintf("Sys call unloaded at %d\n", offset);
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return(error);
}


SYSCALL_MODULE(sysentreplace, &offset, &sysentreplace_sysent, load, NULL);


