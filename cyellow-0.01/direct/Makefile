#
# Makefile for the direct kernel changes that go with curious yellow
#
# - atrak

CC=cc
CFLAGS=-O

default: fix_suser_xxx fix_suser_xxx_kernel

clean:
	rm -f fix_suser_xxx fix_suser_xxx_kernel

fix_suser_xxx:
	$(CC) $(CFLAGS) -o fix_suser_xxx fix_suser_xxx.c -lkvm

fix_suser_xxx_kernel:
	$(CC) $(CFLAGS) -o fix_suser_xxx_kernel fix_suser_xxx_kernel.c -lkvm

