#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

// OK so this code contains the system call definition and the 
// event handler code etc.
// In Kong's book, he defines a struct as follows for the arguments
// to the system call. But it seemed to me that it was not needed.
// Because at the call site we are just passing char * (in this case)
// the call site is in the interface.c program. 
// Also the dispatcher packs these raw arguments into an array of
// register_t types and that array pointer is then cast into a
// void * and passed to the system call below as the second
// parameter. So why have this struct in between? 
// So I knocked it off.
// Later: the struct is needed for elegantly accessing the passed in
// arguments. See below notes.
/*
struct sc_example_args {
	char * str;
};
*/
// The structs below are experimental ones to test out the parameter
// passing aspects.
struct sc_example_goo {
	char * str;
	char * str1;
	char * str2; // str2 was added here to see whether I would get
// some memory violation. I didnt.
};

struct sc_example_goo1 {
	char * str;
};

static int sc_example(struct thread *td, void * syscall_args) {

// The commented code below are from Kong's source. He needs these
// because the argument passed to the syscall is a sc_example_args
// struct. But wait: anothe problem rears its head: how does the
// dispatcher know that it has to take a raw char * passed in at
// the call site into a sc_example_args struct before sticking it
// into the array of register_t types?
// OK, after some angst the answer is clear. Nobody packages
// the passed in parameters into a struct. The second parameter is
// an array of register_t types and syscall_args is a pointer to 
// this array.
// syscall_args ----> |register_t arg1|register_t arg2|register_t arg3|.... 
// By casting the syscall_args to a struct pointer we are basically 
// overlaying the memory pointed to by syscall_args with that struct.

//	struct sc_example_args * uap;
	//uap = (struct sc_example_args *)syscall_args; 
	struct sc_example_goo * uap;
	struct sc_example_goo1 * uap1;
// So when the statement below is executed the conceptual layout will
// be as follows:
// syscall_args ----> |register_t arg1|register_t arg2|register_t arg3|.... 
// uap -------------> |char * str     |char * str2    |char * str3    |
//
	uap = (struct sc_example_goo *)syscall_args; 
	
	register_t * t1 = (register_t *) syscall_args;
// When the statement below is executed the conceptual memory layout
// will be:
// syscall_args ----> |register_t arg1|register_t arg2|register_t arg3|.... 
// uap -------------> |char * str1    |char * str2    |char * str3    |
// uap1 ----------------------------->|char * str     |
// The above happens because we cast syscall_args (which is void *) into
// a register_t * and assigned it to t1. Then we increment t1 so that it
// points to the second slot and then assign that t1 value to the uap1
// pointer. 
// So thus it is clear that we can get at the different parameters easily
// by declaring a struct that matches with the argument list. 
// In the absence of a struct we need to get at the parameters individually. 
	uap1 = (struct sc_example_goo1 *)++t1;

	printf("%s\n", uap->str);
	printf("%s\n", uap->str1);
	printf("%s\n", uap1->str);

// This is how we get at the parameters individually. It is a tad more
// tedious from a syntax perspective.
	char * goo = (char *)((register_t *)syscall_args)[0];
	char * uday = (char *)((register_t *)syscall_args)[1];
	printf("%s %s\n", goo, uday);
// Here I print the addresses of the two variables that point to 
// the passed in arguments. These addresses are the userland addresses
// that are passed into this system call. 
	printf("%p %p\n", goo, uday);

// Testing here to see whether the userland variables are affected
// by an assignment in kernel land. This function executes in kernel
// space but the parameters passed to this are in user space. 
// Of course the userland data is affected. Because the address is
// passed in that points to the userland data: the assignment below
// will cause the userland data to be changed also. I have a printf
// in the interface.c program which will print the value of the
// argument after returning from the system call, and that shows the
// changed value.

// This is bad design and the right way is to copy the data (pointed to
// by the passed in address into a kernel mode structure and then
// manipulate that structure within the system call. 

	goo[1] = 'H';
 	printf("%s\n", goo);

	return 0;
}

static struct sysent sc_example_sysent = {
	2,
	sc_example
};

static int offset = NO_SYSCALL;

static int load(struct module* module, int cmd, void* args) {

	int error = 0;

	switch(cmd) {
		case MOD_LOAD:
			uprintf("OK system call executed\n");
			break;
		case MOD_UNLOAD:
			uprintf("Here is looking at you kid\n");
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return(error);
}

SYSCALL_MODULE(sc_example, &offset, &sc_example_sysent, load, NULL);
