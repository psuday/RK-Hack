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
 *    Tool to read the /kernel at the given offset. Usually you'd pipe 
 *    this into hexdump. No attempt was made at being efficient.
 *
 *    $Id: kread.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
    FILE *fd;
    u_char *buf;
    int length;
    u_int32_t offset;
    
    if(!argv[1] || !argv[2]) {
        fprintf(stderr,"Usage: kread [0xoffset] [length]\n");
        exit(-1);
    }

    offset = strtoul(argv[1],NULL,16);
    length = atoi(argv[2]);

    buf = (u_char *)malloc(length);
    if(!buf) {
        fprintf(stderr,"Unable to allocate memory: %s\n",strerror(errno));
        exit(-1);
    }

    fd = fopen("/kernel","r");
    if(!fd) {
        perror("fopen failed: ");
        exit(-1);
    }

    printf("Reading %d bytes from 0x%x\n",length,offset);

    fseek(fd,offset,SEEK_SET);

    fread(buf,length,1,fd);
    write(STDOUT_FILENO,buf,length);

    fclose(fd);

    exit(0);
}

    

    
