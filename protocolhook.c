#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>

// The incoming data should have the string below and that will
// act as the trigger for the hook to do its work. This is just
// an example.
#define TRIGGER "Shiny"

// We need to access the internals of this struct, and it is not
// declared in a .h file, but is instead buried in a .c file.
// Hence the extern declaration below.
// This is actually an array of protosw structs and there is one element
// for each type of protocol.

extern struct protosw inetsw[];

pr_input_t icmp_input_hook;

//hook code

void icmp_input_hook(struct mbuf * m, int off) {

	struct icmp * icp;

	int hlen = off;
// The ICMP packet is also coming in as a IP packet. So in order to access
// the ICMP packet, we skip the IP header, by incrementing the data pointer
// m_data by the length of the header, hlen. Then the overall message
// length has to be reduced by the header size as well.
// Though for the code below I dont understand the need to 
// manipulate the m buffer structures at all.

// Wouldnt it be possible to just make icp point to the address
// obtained by adding the header length to the m_data pointer?
// Like icp = (struct icmp *)(m->m_data + hlen);

// Let us see ....
/*
	m->m_len -= hlen;
	m->m_data += hlen;

// This information is then fed into the motd macro. This macro is pretty 
// handy and what it does is to convert the pointer passed to it as the
// first argument into the type passed in as the second argument.
	icp = mtod(m, struct icmp *);

	m->m_len += hlen;
	m->m_data -= hlen;

*/

// Well that also worked. 
	icp = (struct icmp *)(m->m_data + hlen);
// So in the if statement below we check whether the icmp packet
// is of interest to us: we check whether it is a particular
// type of packet based on its type and code. And if so then
// check for the payload string.
// If it doesnt match our interests we just let it go.
// In this case we grab the packet if it matches our interest and
// print the appropriate message in turn.

	if (icp->icmp_type == ICMP_REDIRECT &&
		icp->icmp_code == ICMP_REDIRECT_TOSHOST &&
		strncmp(icp->icmp_data, TRIGGER, 5) == 0) {
			printf("OK hook triggered\n");
	} else {
		icmp_input(m, off);
	}
}

static int load(struct module * module, int cmd, void * args) {
	int error = 0;

	switch(cmd) {
		case MOD_LOAD:
// Here is how the hook is accomplished. We place the hook address in the
// input function pointer of the appropriate slot in the inetsw array.
			inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
			break;
		case MOD_UNLOAD:
			inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return error;
}

static moduledata_t icmp_input_hook_mod = {
	"icmp_input_hook",
	load,
	NULL
}; 

DECLARE_MODULE(icmp_input_hook, icmp_input_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

