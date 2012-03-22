// This module was written only to get the disassembled byte codes of the printf
// call in the miswitchhook function.
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

void miswitchhook(void);

void miswitchhook() {
			printf("Current proc id is %d\n", curthread->td_proc->p_pid);
}
	
static int load(struct module * module, int cmd, void * args) {

	int error = 0;
	switch(cmd) {
		case MOD_LOAD:
			miswitchhook();
			break;
		case MOD_UNLOAD:
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}	

	return(error);
}

static moduledata_t mi_switchmodule = {

	"miswitchmodule",
	load,
	NULL
};

DECLARE_MODULE(miswitchmodule, mi_switchmodule, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);


