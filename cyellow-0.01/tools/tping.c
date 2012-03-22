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
 *    Tool to send a spoofed icmp echo packet with the specified payload.
 *
 *    $Id: tping.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */

#include <stdio.h>
#include <libnet.h>

#define TPING_ID 123
#define TPING_TTL 48

void usage();

int
main(int argc, char **argv)
{

    int sock, n, c, r, p_num;
    struct libnet_arena arena, *arena_p;
    u_char *packets[10];
    u_char *payload;
    u_char *buf;
    u_long src_ip, dst_ip;
    
    src_ip = 0;
    dst_ip = 0;
    payload = NULL;

    while((c = getopt(argc, argv, "d:s:p:")) != EOF)
    {
        switch (c)
        {
            case 'd':
                if (!(dst_ip = libnet_name_resolve(optarg, 1))) {
                    fprintf(stderr, "Bad destination IP address: %s\n", optarg);
                    exit(1);
                }
                break;

            case 's':
                if (!(src_ip = libnet_name_resolve(optarg, 1))) {
                    fprintf(stderr, "Bad source IP address: %s\n", optarg);
                    exit(-1);
                }
                break;

            case 'p':
                payload = optarg;
                break;
            
            default:
                usage();
                exit(-1);
        }
    }

    if (!src_ip || !dst_ip || !payload) {
        usage();
        exit(-1);
    }

    /* allocate packet memory */
    buf = (u_char *)malloc(LIBNET_IP_H + LIBNET_ICMP_H + strlen(payload));
    if(!buf) {
        perror("malloc:");
        exit(-1);
    }
    
    sock = libnet_open_raw_sock(IPPROTO_RAW);
    if (sock == -1) {
        perror("No socket");
        exit(-1);
    }
   
    /* build headers */ 
    libnet_build_ip(LIBNET_ICMP_ECHO_H, IPTOS_LOWDELAY | IPTOS_THROUGHPUT,  
        TPING_ID,  0, TPING_TTL, IPPROTO_ICMP, src_ip, dst_ip, NULL, 0, buf);

    libnet_build_icmp_echo(ICMP_ECHO, 0, TPING_ID, 1, payload,strlen(payload),
                buf + LIBNET_IP_H);
 

    if (libnet_do_checksum(buf, IPPROTO_ICMP, LIBNET_ICMP_ECHO_H) < 0) {
        fprintf(stderr, "Can't do checksum!\n");
    }

    /*
    *  Write the packet to the network.
    */
    r = libnet_write_ip(sock, buf, LIBNET_ICMP_ECHO_H + LIBNET_IP_H + strlen(payload));
    if (r < LIBNET_ICMP_ECHO_H + LIBNET_IP_H + strlen(payload)) {
        fprintf(stderr, "Unable to send packet.\n");
    }

    printf("ICMP Echo sent. Payload: %s\n",payload);

}

void
usage()
{
    fprintf(stderr,"Usage: tping -s [source] -d [dest] -p [payload]\n");
}


