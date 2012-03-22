# Makefile for building the sample syscall module

SRCS	= cyellow.c util.c file-sysc.c control.c process.c fw.c exec.c icmp.c file-ufs.c
KMOD	= cyellow
KO	= ${KMOD}.ko
KLDMOD	= t

KLDLOAD		= /sbin/kldload
KLDUNLOAD	= /sbin/kldunload

load: ${KO}
	${KLDLOAD} -v ./${KO}

unload: ${KO}
	${KLDUNLOAD} -v -n ${KO}

.include <bsd.kmod.mk>
