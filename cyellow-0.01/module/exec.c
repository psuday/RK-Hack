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
 *    $Id: exec.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This is an example on how to execute a program from within the
 *    kernel. Other syscalls can be made accordingly. 
 *
 *    This stuff was written for educational purposes only. 
 */
    
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/acct.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/wait.h>
#include <sys/proc.h>
#include <sys/pioctl.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/sysent.h>
#include <sys/shm.h>
#include <sys/sysctl.h>
#include <sys/resourcevar.h>
#include <sys/sysproto.h>
#include <sys/unistd.h>
#include <sys/select.h>
#include <sys/mman.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>

#include <machine/pmap.h>
#include <machine/vmparam.h>

/* #include "vnode.h" */
#include <vnode.h>

#include "../config.h"
#include "util.h"
#include "exec.h"

#ifdef KERNEL_EXEC

extern register_t *exec_copyout_strings __P((struct image_params *));
extern u_long ps_strings;
extern u_long usrstack;
extern const struct execsw **execsw;

MALLOC_DEFINE(M_PARGS, "proc-args", "Process arguments");


/*
    execute the given program from kernel space, calls execve
*/

#define PROGRAM "/home/atrak/test"

int 
start_prog(void)
{
    int error;
    char *path = PROGRAM;
    vm_offset_t base, addr;
    struct proc *ep;
    struct execve_args *args;
    struct vmspace *vm;

    ep = curproc;
    if(!ep) {
        printf("No curproc\n");
        return(EFAULT);
    }

    /* allocate memory for the arguments, say PAGE_SIZE big */
    vm = ep->p_vmspace;
    base = round_page((vm_offset_t) vm->vm_daddr);
    addr = base + ctob(vm->vm_dsize);

    error = vm_map_find(&vm->vm_map, NULL, 0, &addr, PAGE_SIZE,
            FALSE, VM_PROT_ALL, VM_PROT_ALL, 0);

    if(error) {
                printf("start_prog: couldn't allocate argument space: %d",error);
                return(EFAULT);
    }

    vm->vm_dsize += btoc(PAGE_SIZE);

    addr = base + ctob(vm->vm_dsize) - PAGE_SIZE;
    args = (struct execve_args *)addr;

    /* Set the desired filename, no arguments */
    args->fname = (char *)(addr + sizeof(struct execve_args));
    copyout(path,args->fname,strlen(path));
   
    args->argv = NULL;
    args->envv = NULL;

    /* actually execute the program */

    error = execve(ep, args);
    if(error) {
        printf("can't execve\n");
        return(error);
    }

    return(error);
}

#endif /* KERNEL_EXEC */
