// This code will contain a manic hello world that will print
// 10 times. The objective is to patch the byte codes of the
// syscall so that this behavior is removed.

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

// OK I have done some minor changes to the hello syscall code.
// There are two strings defined below and strcmp which seemingly
// does nothing. Well the idea was to patch the kernel memory
// so that a) the loop is removed and b) the str2 is substituted
// with the str1.
// The strcmp is needed because I need to use the string in some
// way as otherwise in the compiled code the reference to that
// is optimized away.

static int hello(struct thread * td, void * syscall_args) {
	int i;
	char * str1 = "Hello my friend, you are going to die\n"; 
	char * str2 = "Tou cant handle the truth\n"; 
	strcmp(str1, str2);
	for (i = 0; i < 10; i++) {
		printf("%s",str2);
	}

	return 0;
}

static struct sysent hello_sysent = {
	0,
	hello
};

static int offset = NO_SYSCALL;

static int load(struct module * module, int cmd, void * arg) {

	int error = 0;

	switch(cmd) {
		case MOD_LOAD:
			uprintf("System call loaded at offset %d\n", offset);
			break;
		case MOD_UNLOAD:
			uprintf("System call unloaded from offset %d\n", offset);			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return error;
}

SYSCALL_MODULE(hello, &offset, &hello_sysent, load, NULL);
