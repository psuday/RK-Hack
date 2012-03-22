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
 *    Tool to read /dev/kmem at the given offset.  Usually you'd pipe 
 *    this into hexdump. No attempt is being made at being efficient. :)
 *
 *    $Id: kvmread.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
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


int main(int argc, char **argv)
{
    int i;
    char *buf;
    char errbuf[_POSIX2_LINE_MAX];
    int length;
    u_int32_t offset;
    kvm_t *kd;
    struct nlist nl[] = { { NULL }, { NULL }, };

    if(!argv[1] || !argv[2]) {
        fprintf(stderr,"Usage: kvmread [0xoffset] [length]\n");
        exit(-1);
    }

    offset = strtoul(argv[1],NULL,16);
    length = atoi(argv[2]);

    buf = (u_char *)malloc(length);
    if(!buf) {
        fprintf(stderr,"Unable to allocate memory: %s\n",strerror(errno));
        exit(-1);
    }

    nl[0].n_name = argv[1];

    kd = kvm_openfiles(NULL,NULL,NULL,O_RDONLY,errbuf);
    if(kd == NULL) {
        fprintf(stderr,"ERROR: %s\n",errbuf);
        exit(-1);
    }

    kvm_read(kd, offset, buf, length);
    write(STDOUT_FILENO,buf,length);

    if(kvm_close(kd) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    exit(0);

}
