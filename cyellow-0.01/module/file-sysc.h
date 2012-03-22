
#ifndef _FILE_SYSC_H
#define _FILE_SYSC_H

#include "../config.h"
#include <sys/sysproto.h>

#ifdef FILE_SYSCALLS

extern int new_open(struct proc *, register struct open_args *);
extern int new_stat(struct proc *, register struct stat_args *);
extern int new_lstat(struct proc *, register struct lstat_args *);
extern int new_chflags(struct proc *, register struct chflags_args *);
extern int new_chmod(struct proc *, register struct chmod_args *);
extern int new_chown(struct proc *, register struct chown_args *);
extern int new_utimes(struct proc *, register struct utimes_args *);
extern int new_truncate(struct proc *, register struct truncate_args *);
extern int new_rename(struct proc *, register struct rename_args *);
extern int new_unlink(struct proc *, register struct unlink_args *);
extern int new_getdirentries(struct proc *, register struct getdirentries_args *);

#define AS(name) (sizeof(struct name) / sizeof(register_t))

static struct sysent new_open_sysent = {
        AS(open_args),
        (sy_call_t *)new_open
};

static struct sysent new_getdirentries_sysent = {
        AS(getdirentries_args),
        (sy_call_t *)new_getdirentries
};

static struct sysent new_stat_sysent = {
        AS(stat_args),
        (sy_call_t *)new_stat
};

static struct sysent new_lstat_sysent = {
        AS(lstat_args),
        (sy_call_t *)new_lstat
};

static struct sysent new_chflags_sysent = {
        AS(chflags_args),
        (sy_call_t *)new_chflags
};

static struct sysent new_chmod_sysent = {
        AS(chmod_args),
        (sy_call_t *)new_chmod
};

static struct sysent new_chown_sysent = {
        AS(chown_args),
        (sy_call_t *)new_chown
};

static struct sysent new_utimes_sysent = {
        AS(utimes_args),
        (sy_call_t *)new_utimes
};

static struct sysent new_truncate_sysent = {
        AS(truncate_args),
        (sy_call_t *)new_truncate
};

static struct sysent new_rename_sysent = {
        AS(rename_args),
        (sy_call_t *)new_rename
};

static struct sysent new_unlink_sysent = {
        AS(unlink_args),
        (sy_call_t *)new_unlink
};

#endif /* FILE_SYSCALLS */

#endif /* _FILE_SYSC_H */

