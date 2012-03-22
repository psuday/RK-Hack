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
 *    This will check if sysent[CALL] is really the specified system call. 
 *    Do checksys fix in order to change it back to the original function.
 *
 *    This could be used to fix calls entered by rogue modules, but also 
 *    in return a rogue user could use this to check if you have one of the
 *    load module logging traps installed and circumvent it, so beware.
 *
 *    Again, this software was written for educational purposes only.
 *
 *    $Id: checkcall.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */

#include <stdio.h>
#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/syscall.h>

void usage();

int
main(int argc, char **argv) {

    kvm_t *kd;
    u_int32_t addr;
    int callnum;
    struct sysent call;
    char errbuf[_POSIX2_LINE_MAX];
    struct nlist nl[] = { { NULL }, { NULL }, { NULL }, };

    /* check arguments */
    if(argc < 3) {
        usage();
        exit(-1);
    }

    nl[0].n_name = "sysent";
    nl[1].n_name = argv[1]; 
    callnum = atoi(argv[2]);

    printf("Checking syscall %d: %s\n\n",callnum,argv[1]);

    kd = kvm_openfiles(NULL,NULL,NULL,O_RDWR,errbuf);
    if(!kd) {
        fprintf(stderr,"ERROR: %s\n",errbuf);
	exit(-1);
    }

    /* find the location of sysent */
    if(kvm_nlist(kd,nl) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    if(nl[0].n_value) 
        printf("%s is 0x%x at 0x%x\n",nl[0].n_name,nl[0].n_type,nl[0].n_value);	
    else {
        fprintf(stderr,"ERROR: %s not found (very weird...)\n",nl[0].n_name);
        exit(-1);
    }

    if(!nl[1].n_value) {
        fprintf(stderr,"ERROR: %s not found\n",nl[1].n_name);
        exit(-1);
    }

    /* find the location of sysent[callnum] */
    addr = nl[0].n_value + callnum * sizeof(struct sysent);

    /* find out where it points to */
    kvm_read(kd, addr, &call, sizeof(struct sysent));
    printf("sysent[%d] is at 0x%x and will go to function at 0x%x\n",callnum,addr,call.sy_call);

    /* check if that's correct */
    if((u_int32_t)call.sy_call != nl[1].n_value)  {
        printf("ALERT! It should go to 0x%x instead\n",nl[1].n_value);

        /* see if it should be fixed */
        if(argv[3] && !strcmp(argv[3],"fix")) {
            printf("Fixing it..");

            (u_int32_t)call.sy_call = nl[1].n_value;
            if(kvm_write(kd, addr, &call, sizeof(struct sysent)) < 0) {
                fprintf(stderr,"ERROR: Unable to write %s\n",kvm_geterr(kd));
                exit(-1);
            }

            printf("Done.\n");
        }
    }
    
        
    if(kvm_close(kd) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    exit(0);
}

void
usage()
{
    fprintf(stderr,"Usage: checkcall [name of the syscall function] [call number] <fix>\n\n");
    fprintf(stderr,"see /sys/sys/syscall.h for the call numbers\n");
}
