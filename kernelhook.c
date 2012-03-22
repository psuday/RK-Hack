// Here we do the hooking process. This is akin to code injection.
// So we will fix the system call so that our code gets executed
// before the actual system call is executed.
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

static int kld_hook(struct thread * td, void * syscall_args) {

// This is the code that we want to inject into the path of an 
// existing system call. The interface is the same as that of a 
// system call. In other words this routine could be inserted
// into the next empty slot of the sysent table. 
	struct kld_args {
		char * str;
	} * uap;

	uap = (struct kld_args *) syscall_args;

	char mname[255];
	size_t done;
	int error;

        error =	copyinstr(uap->str, mname, 255, &done);

	if (error != 0) {
		return(error);
	}

// The printf below is our "sinister" payload. 
	uprintf("The module that is being loaded into the kernel is %s\n",
		mname); 
// And once that payload is executed, control transfers to the original
// system call that we have hooked.

	return(kldload(td, syscall_args));

}

// load and unload event handler.
// Now we have to understand clearly the connection between a loadable
// kernel module, hook function etc. This entire program defines a
// loadable kernel module. When this module is loaded into the 
// kernel as a result of a kldload call, the function below is invoked
// because it is defined as the event handler for this module in the
// DECLARE_MODULE call below - via the module data struct.
// 

static int load(struct module* module, int cmd, void * arg) {

	int error = 0;

	switch(cmd) {
// The only difference here from the system call code is that
// instead of registering a new system call: we replace the 
// function pointer in an existing system call with
// the new code. That is our code, and it will do whatever it does
// need to do and then transfer control to the existing system call.
		case MOD_LOAD:
// Here below the nefarious hooking happens.
			sysent[SYS_kldload].sy_call = (sy_call_t *)kld_hook;
			break;
		case MOD_UNLOAD:
			sysent[SYS_kldload].sy_call = (sy_call_t *)kldload;
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return(error);
}

static moduledata_t kld_hook_mod = {
		"kld_hook",
		load,
		NULL
};

DECLARE_MODULE(kld_hook, kld_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);


