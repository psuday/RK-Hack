// This system call will dump a formatted output of sysent.
// This will take two parameters: 1) base address of sysent table
// and 2) the index to dump.

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

struct sysentdisplay_args {

	unsigned long address;
	int index;
};

static int sysentdisplay(struct thread * td, void * syscall_args) {

	uprintf("Entered the sysentdisplay syscall\n");
	struct sysentdisplay_args *uap = (struct sysentdisplay_args *)syscall_args;
	struct sysent *s = (struct sysent *)uap->address;
	
	uprintf("No of args is %d\n", s[uap->index].sy_narg); 

	uprintf("Address of implementing function %lx\n", (unsigned long)s[uap->index].sy_call);
	
	return 0;

}

static struct sysent sysentdisplay_sysent = {
	2,
	sysentdisplay
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


SYSCALL_MODULE(sysentdisplay, &offset, &sysentdisplay_sysent, load, NULL);


