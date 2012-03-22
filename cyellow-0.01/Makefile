#
# Makefile for Curious Yellow 0.01
#
# - atrak, 04/08/2001
#

# Set this to your own config directory
KERNELNAME=/sys/compile/ONO/

default: 
	cp $(KERNELNAME)/vnode_if.h module/replace/
	cp $(KERNELNAME)/opt_ipsec.h module/replace/
	cp $(KERNELNAME)/faith.h module/replace/
	cd module; make
	cd tools; make
	cd direct; make
	cd exp; make
	cd exp; cc -o setsym setsym.c
	cd trapmod; make

clean:
	cd module; make clean
	cd tools; make clean
	cd direct; make clean
	cd exp; make clean
	cd exp; rm -f setsym
	cd trapmod; make clean

load:
	cd module; make load

unload:
	cd module; make unload

