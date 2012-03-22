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
 *    $Id: symtable.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This loads a system call that allows you to set the address of a symbol
 *    in the symbol table. This is quite experimental, so use with care. 
 *
 *    This is written for educational purposes only. (I'm starting to repeat
 *    myself I know :) )
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
#include <machine/elf.h>

#include "symtable.h"

#define DEBUG 1

#define mod_debug(format, args...)  if(DEBUG) printf(format, ## args)

/* external symbols in the kernel */
extern linker_file_list_t linker_files;
extern unsigned long elf_hash(const char *);

/* description of this system call */
static struct sysent set_symbol_sysent = {
        2,                
        set_symbol
};

/* offset in sysent where it will be loaded */
static int offset = NO_SYSCALL;

/* 
 *    experimental system call to set the value of a symbol in the
 *    symbol table. 
 */

int
set_symbol(struct proc *p, struct set_symbol_args *uap)
{

    linker_file_t lf;
    elf_file_t ef;
    unsigned long symnum;
    const Elf_Sym* symp = NULL;
    Elf_Sym new_symp;
    const char *strp;
    unsigned long hash;
    caddr_t address;
    int error = 0;

    mod_debug("Set symbol %s address 0x%x\n",uap->name,uap->address);

    lf = TAILQ_FIRST(&linker_files);
    ef = lf->priv;

    /* First, search hashed global symbols */
    hash = elf_hash(uap->name);
    symnum = ef->buckets[hash % ef->nbuckets];

    while (symnum != STN_UNDEF) {
        if (symnum >= ef->nchains) {
            printf("link_elf_lookup_symbol: corrupt symbol table\n");
            return ENOENT;
        }

        symp = ef->symtab + symnum;
        if (symp->st_name == 0) {
            printf("link_elf_lookup_symbol: corrupt symbol table\n");
            return ENOENT;
        }

        strp = ef->strtab + symp->st_name;

        if (!strcmp(uap->name, strp)) {

            /* found the symbol with the given name */
            if (symp->st_shndx != SHN_UNDEF ||
                (symp->st_value != 0 && ELF_ST_TYPE(symp->st_info) == STT_FUNC)) {

                /* give some debug info */
                address = (caddr_t) ef->address + symp->st_value;
                mod_debug("found %s at 0x%x!\n",uap->name,(uintptr_t)address);

                bcopy(symp,&new_symp,sizeof(Elf_Sym));
                new_symp.st_value = uap->address;

                address = (caddr_t) ef->address + new_symp.st_value;
                mod_debug("new address is 0x%x\n",(uintptr_t)address);

                /* set the address */
                bcopy(&new_symp,(ef->symtab + symnum),sizeof(Elf_Sym)); 

                break;

            } else
                return(ENOENT);
        }

        symnum = ef->chains[symnum];
    }    

    /* for now this only looks at the global symbol table */

    return(error);
}

/* this will be called when the module is loaded/unloaded */

static int
load (struct module *module, int cmd, void *arg)
{
        int error = 0;

        switch (cmd) {
        case MOD_LOAD :
                printf ("set_symbol loaded at %d\n", offset);
                break;
        case MOD_UNLOAD :
                printf ("set_symbol unloaded from %d\n", offset);
                break;
        default :
                error = EINVAL;
                break;
        }
        return error;
}

SYSCALL_MODULE(symtable, &offset, &set_symbol_sysent, load, NULL);

