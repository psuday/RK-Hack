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
 *    $Id: setsym.c,v 1.1.1.1 2001/08/06 12:02:07 atrak Exp $
 *
 *    Small tool to set the address of a symbol using the system call
 *    set_symbol in symtable.c
 *
 *    This was written for educational purposes only.
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <errno.h>

int
main(int argc, char **argv)
{
    int num;
    char *name;
    u_int32_t address;
    struct module_stat stat;

    if(argc < 3) {
        fprintf(stderr,"Usage: setsym [0xaddress] [symbolname]\n");
        exit(-1);
    }

    address = strtoul(argv[1],NULL,16);
    name = argv[2];

    /* first of all find the module */
    stat.version = sizeof(stat);

    if(modstat(modfind("symtable"), &stat) != 0) {
        fprintf(stderr,"Can't locate the module\n");
        exit(-1);
    }
    num = stat.data.intval;

    if(syscall (num,address,name) != 0) {
        fprintf(stderr,"Unable to set %s to address 0x%x: %s\n",name,address,strerror(errno));
        exit(-1);
    }
}

