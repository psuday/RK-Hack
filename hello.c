#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>

/* OK this source is from Joseph Kong's book on Designing BSD Rootkits.
This code is in 1.3 Chapter 1.


The function that will be called during module load and unload


The function below is the event handler and it has to conform
to a specific interface, which is defined by the prototype 
in sys/module.h

typedef int (*modeventhand_t) (module_t, int, void *);

The hairy typedef above defines a function pointer which returns
int and takes three parameters. The second parameter is an enum
which defines the different events such as module load, unload
etc. If the event handler needs to consume arguments that is passed
as the third parameter.

module_t is a pointer to the module struct

The module struct seems to be elusive, I have no idea what it
looks like.

Not anymore: I tracked down the elusive pimpernel. It resides in the
folder and the C module below. The C module defines the struct. Then
it is compiled and linked in when the loadable module is created.


/usr/src/sys/kern/kern_module.c
*/
static int load(struct module *module, int cmd, void * args) {
	int error = 0;

	switch(cmd) {
		case MOD_LOAD:
			uprintf("Hello Sexy\n");
			break;
		case MOD_UNLOAD:
			uprintf("Down with Bush\n");
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}
	

	return error;
}

static moduledata_t hello_mod = {
	"hello",
	load,
	NULL
};


DECLARE_MODULE(hello, hello_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);



	
