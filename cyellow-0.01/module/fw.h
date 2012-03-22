
#ifndef _FW_H
#define _FW_H

#include <sys/socketvar.h>

int hide_rule(u_short);
int unhide_rule(u_short);

int new_ip_fw_ctl(struct sockopt *);


#endif _FW_H
