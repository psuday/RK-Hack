// This is similar to modfindtest.c but still different. Heh heh/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>

#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

#include <sys/dirent.h>

struct module {
	TAILQ_ENTRY(module)	link;
	TAILQ_ENTRY(module)	flink;
	struct linker_file	*file;
	int			refs;
	int			id;
	char			*name;
	modeventhand_t		handler;
	void			*arg;
	modspecific_t		data;
};
static int load(struct module * module, int cmd, void * arg) {
// So this is how we can invoke event handlers in any arbitrary
// module. First we use the convenient module_lookupbyname
// routine which is defined in line 219 of the /sys/kern/kern_module.c
// This will return a module * type. Then we can invoke the event
// handler in that module. Here we assemble a parameter array
// consisting of two unsigned long values (addresses) and then
// after doing a sanity check on the returned pointer, we invoked
// the handler with the parameters. The second parameter is an arbitrary
// integer which defines the specific type of event that is dispatched.
// /sys/sys/module.h declares an enum modeventtype which defines
// four types of events: MOD_LOAD, MOD_UNLOAD, MOD_SHUTDOWN, 
// MOD_QUIESCE. These are integers 0, 1, 2, 3. So I picked 6 to be
// the new event type.
	char * s1;
	switch(cmd) {
		case MOD_LOAD:
			s1 = (char *)arg;
			module_t mod  = module_lookupbyname("kldhide");
			unsigned long args[] = {0xc36e6100, 0xc341ee00};
			if(mod) mod->handler(mod, 6, args);
			break;

	case MOD_UNLOAD:
			break; 
	default:
		break;
	}


	return(0);
}

static moduledata_t modcalltest_dat = {
	"modcalltest",
	load,
	NULL
	};

DECLARE_MODULE(modcalltest, modcalltest_dat, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
