#
# Makefile for the tools that go with curious yellow
#
# - atrak

CC=cc
CFLAGS=-O

default: cyctl tping findsym kread putjump putreturn kvmread checkcall listprocs

clean:
	rm -f cyctl tping findsym kread putreturn putjump kvmread checkcall listprocs

cyctl:
	$(CC) $(CFLAGS) -o cyctl cyctl.c

findsym:
	$(CC) $(CFLAGS) -o findsym findsym.c -lkvm

listprocs:
	$(CC) $(CFLAGS) -o listprocs listprocs.c -lkvm

checkcall:
	$(CC) $(CFLAGS) -o checkcall checkcall.c -lkvm

kvmread:
	$(CC) $(CFLAGS) -o kvmread kvmread.c -lkvm

putjump:
	$(CC) $(CFLAGS) -o putjump putjump.c -lkvm

putreturn:
	$(CC) $(CFLAGS) -o putreturn putreturn.c -lkvm

tping:
	$(CC) -I /usr/local/include -o tping tping.c `libnet-config --defines` -L/usr/local/lib -lnet
