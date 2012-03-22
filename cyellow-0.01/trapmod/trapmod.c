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
 *    $Id: trapmod.c,v 1.1.1.1 2001/08/06 12:02:07 atrak Exp $
 *
 *    This is a small module that replaced the kldload system call
 *    to make the fact that someone loaded a module known. Right now
 *    this just prints a message. Other ways of keeping track of 
 *    possible rogue methods would be possible.
 */

#include <sys/param.h> 
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/fcntl.h>   
#include <sys/libkern.h>   
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/linker.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <machine/elf.h>

#include "config.h"
#include "trapmod.h"

#define mod_debug(format, args...)  if(DEBUG) printf(format, ## args)
#define AS(name) (sizeof(struct name) / sizeof(register_t))

/* description of this system call */
static struct sysent trapmod_sysent = {
        AS(kldload_args),                
        (sy_call_t *)trapmod
};

/* offset in sysent where it will be loaded */
static int offset = NO_SYSCALL;

/* 
 *    This will just send out a printf when someone loads a module
 *    change appropriately
 */

int
trapmod(struct proc *p, struct kldload_args *uap)
{
    printf("NOTE: Someone's loading a module\n");

    return(kldload(p,uap));
}

/* this will be called when the module is loaded/unloaded */

static int
load (struct module *module, int cmd, void *arg)
{
        int error = 0;
#ifdef STEALTH
        linker_file_t lf = 0;
        module_t mod = 0;
#endif

        switch (cmd) {
        case MOD_LOAD :

            mod_debug("Loading Trapmod\n");

            mod_debug("Replacing kldload\n");
            sysent[SYS_kldload] = trapmod_sysent;
            
#ifdef STEALTH

            /* go to stealth mode, eg hide the module itself, inspired by the thc article */

            (&linker_files)->tqh_first->refs--;

            TAILQ_FOREACH(lf, &linker_files, link) {

                if (!strcmp(lf->filename, "trapmod.ko")) {

                   /*first let's decrement the global link file counter*/
                   next_file_id--;

                   /*now let's remove the entry*/
                   TAILQ_REMOVE(&linker_files, lf, link);
                   break;    
                }
            } 

            TAILQ_FOREACH(mod, &modules, link) {

                if(!strcmp(mod->name, "trapmod")) {
                    /*first let's patch the internal ID counter*/
                    nextid--;

                    TAILQ_REMOVE(&modules, mod, link);
                }
            }

#endif 
                break;
        case MOD_UNLOAD :

                mod_debug("Unloading Trapmod\n");

                mod_debug("Restoring kldload\n");
                sysent[SYS_kldload].sy_call = (sy_call_t *)kldload;

                break;
        default :
                error = EINVAL;
                break;
        }
        return error;
}

SYSCALL_MODULE(trapmod, &offset, &trapmod_sysent, load, NULL);

