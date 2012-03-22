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
 *    This is a tool to list the processess directly from /dev/kmem.
 *    Other structures could be read from the kernel in the same way.
 *    This is just a small example on how to do this.
 * 
 *    $Id: listprocs.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <fcntl.h>
#include <nlist.h>
#include <kvm.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/queue.h>

LIST_HEAD(proclist, proc);

int main(int argc, char **argv)
{
    int i;
    char *buf;
    kvm_t *kd;
    struct proc *p_ptr, p;
    struct pcred cred;
    struct proclist allproc;
    char errbuf[_POSIX2_LINE_MAX];
    struct nlist nl[] = { { NULL }, { NULL }, };

    nl[0].n_name = "allproc";

    kd = kvm_openfiles(NULL,NULL,NULL,O_RDONLY,errbuf);
    if(!kd) {
        fprintf(stderr,"ERROR: %s\n",errbuf);
        exit(-1);
    }

    /* find the location of allproc */
    if(kvm_nlist(kd,nl) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    if(!nl[0].n_value) {
        /* very weird indeed */
        fprintf(stderr,"ERROR: allproc not found (very weird...)\n");
        exit(-1);
    }

    kvm_read(kd,nl[0].n_value, &allproc, sizeof(struct proclist));

    printf("PID\tUID\n\n");

    for(p_ptr = allproc.lh_first; p_ptr; p_ptr = p.p_list.le_next) {

        /* read this proc structure */
        kvm_read(kd,(u_int32_t)p_ptr, &p, sizeof(struct proc));
        kvm_read(kd,(u_int32_t)p.p_cred, &cred, sizeof(struct pcred));

        printf("%d\t%d\n", p.p_pid, cred.p_ruid);

    }

    if(kvm_close(kd) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    exit(0);
}
