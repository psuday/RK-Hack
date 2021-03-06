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
 *    Patch a return into the kernel. This means the specified function
 *    will return right away and not do anything. This is basically more
 *    of a demo.
 *
 *    $Id: putreturn.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */

#include <stdio.h>
#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <limits.h>

/* return instruction */
unsigned char code[] = { 0xc3 };

int
main(int argc, char **argv) {

    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd;
    struct nlist nl[] = { { NULL }, { NULL }, };

    if(argc < 2) {
        fprintf(stderr,"Usage: putret [function]\n");
        exit(-1);
    }

    nl[0].n_name = argv[1];

    kd = kvm_openfiles(NULL,NULL,NULL,O_RDWR,errbuf);
    if(kd == NULL) {
        fprintf(stderr,"ERROR: %s\n",errbuf);
        exit(-1);
    }

    /* retrieve symbol information */
    if(kvm_nlist(kd,nl) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    if(!nl[0].n_value) {
        fprintf(stderr,"Symbol %s not found.\n",nl[0].n_name);
        exit(-1);
    }

    printf("%s is 0x%x at 0x%x\n",nl[0].n_name,nl[0].n_type,nl[0].n_value);	

    /* write the instruction to the specified address */
    if(kvm_write(kd,nl[0].n_value,code,sizeof(code)) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    printf("Written return to %s\n",nl[0].n_name);

    if(kvm_close(kd) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    exit(0);
}
