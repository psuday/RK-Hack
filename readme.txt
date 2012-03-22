Wed Jan 20 18:38:52 UTC 2010 Fremont

This folder contains rootkit code from Joseph Kong's book.

It starts off with an illustration of how to write kernel loadable
modules and system calls. 

So far everything is working fine. 

Thu Jan 21 14:07:51 UTC 2010 Fremont, still

Meanwhile I did some arcane work on the system call programs. I wanted
to know how the syscall_args parameter works. I have recorded this inline
in the code. 

The sys/sysproto.h file is useful for packaging the system call arguments into
well padded register_t entries. The register_t is the same size as int in
the BSD machine. The file was also needed to avoid an AUE_NULL error when
I compiled the sc_example.c routine. The error occurred in the SYSCALL_
MODULE call.

Thu Jan 21 18:22:02 UTC 2010 Fremont, still

The rains have subsided. I like rainy weather.  

I have completed work on the first chapter of Kong's book. I must admit
that I becoming attached to the FreeBSD OS. The main attraction is that
it is a complete free operating system as opposed to Linux which is just
the kernel and we need to rely on other distros for the complete OS.

There is a site at www.lemis.com where Greg Lehey has a wealth of 
information including two books about the FreeBSD OS. He also
has information regarding Kernel debugging etc. This site is similar
to Paul Hsieh's site which I used to frequent earlier during my
Game porting days. That seems so far away now.

And then there is such complete information on the freebsd.org site
which is also quite refreshing. 

I must be careful that I dont get sucked in.


Fri Jan 22 17:11:13 UTC 2010 SC

OK, there have been many developments.  First of all I was wondering
whether I could move a virtual hard disk from one VBox environment
to another. For example, I had the bsdbox.vdi (this hard disk) 
"installed" in the Cisco host machine's VBox. Now I wanted to move
it to the CSC host machine's VBox. But for that I had to transfer
the nearly 8 GB virtual hard disk from one machine to another.

Since it was difficult to compress the file and since I didnt have
any high capacity tapes etc. I realized that one way was to network
the two machines together. A little bit of internet research revealed
the two options: 1) Use an Ethernet cross over cable that connects
the two Ethernet interfaces together. 2) Use the Computer to Computer
adhoc networking option in the Wireless network to connect the computers
together.

For option 2: we have to go into the Wireless network tab after clicking
on properties in the Wireless network entry in Network Connections.
Then in Advanced panel we change the wireless connection to peer to peer.
We now create a new connection and name it etc, just as we would for creating
a normal connection.

Then we connect to the newly created network. In computer 2 we locate the
new network that we just created and connect to it. After that if we 
go to Network places and search for the other computer it should show up.
Then we can transfer files after first sharing the required folders.

The problem here was it was just too damn slow. And also the internet
connection on either computer was removed because I had only wireless
interface. 

So I tried out option 1: this was as simple as connecting the ethernet
cable to the two ethernet interfaces in either computer. After that
the same search, sharing etc, can be used for sharing the files. This
was much faster.  I thus transferred the virtual hard disk to 
the CSC machine. Now the wireless connection is not disturbed and
the lan connection is also operational, good.

The next step was to find out whether the VBox would accept the copied 
virtual hard disk: it did and booted FreeBSD. After that I wanted
to see whether I could network the two VMs together. 

The VBox help (online help) chapter 6 gave some meager instructions. 
The gist of it was to create a host only or internal network. The internal
network was the better option as it is more secure and bypasses the host's
network interface completely. 

For this we could use the GUI but that doesnt work properly.

Instead there are command line interface commands that should be run on the
host OS. Thus in the Windows Command line prompt the following should be
run:

vboxmanage.exe modifyvm bsdbox -nic2 <name>
vboxmanage.exe modifyvm bsdbox -intnet2 <name> (can be a different name)
vboxmanage.exe modifyvm linuxbox -nic2 <name>
vboxmanage.exe modifyvm linuxbox -intnet2 <name> (can be a different name)


The nic2 and intnet2 refers to the second adapter. The first adapter
is still used to connect to the host through NAT.

After this we need to go into each box and assign an IP address to the
network interface. 

First run ifconfig and check the name of the interface: if the first one
is eth0 the next one will be eth1. So to assign an IP address the following
command can be run from the cli:

ifconfig eth1 192.168.1.10

and on the other machine

ifconfig em1 192.168.1.11

The two IP addresses can be anything as long as they are on the same
subnet.

Once these are done then you can test the network by pinging it
from each other

ping 192.168.1.10 (from 192.168.1.11) and vice versa.

Now files can be moved by scp, login can be done by ssh etc.

For ssh to work sshd should be running. 

I spent some time trying to find out what was wrong when I tried to access
the bsdbox from the linuxbox with a command like this:

ssh 192.168.1.11 ls

This assumes root login by default and the bsd box refused this.
The /etc/ssh/sshd_config file has to be edited and the commented
lines have to be uncommented and the correct option should be set.

This PermitRootLogin no if commented doesnt necessarily mean that root
login is allowed. 

Instead the line should be uncommented and PermitRootLogin yes should
be typed. Then sshd should be restarted and the new settings will
take effect and the ssh will work. 

Arcane stuff, but now the machines talk to each other. 


Tue Jan 26 01:34:10 UTC 2010 Fremont, CA

There is some code that is used to hide the process and that simply 
removes the proc struct from the all proc list. But there should 
be a way to put the proc struct back on the list as well. That should 
be a good modification to the proc hiding code. 

Fri Jan 29 14:56:13 UTC 2010 Fremont, CA

I have been wandering around, I have not gone to office since last
Monday. Nobody questions me. Sometimes I feel a sense of fear, but
every time I realize that I have to accept all possible choices.

I got sidetracked into networking two computers together. I found
that the domain and xp work group dont work together at all. I couldnt
share files or anything else. For two domain computers (in different
domains) the ethernet cable worked fine: but when I tried it from the
Cisco computer it was very slow in pulling a file from the CSC machine
but the CSC machine end was much faster, whether it was a push or a pull.
I am not sure why that is the case. 

But in either case, the prerequisite for the file transfer is that each
computer is able to ping the other's network interface.

Then I got sidetracked into figuring out how to modify the configuration
of the system console. I didnt have any luck in using the vidcontrol
utility to change the video settings. The screen became big but the
fonts were kind of screwed up.

Finally I had to give up. 


Mon Feb  1 14:28:57 UTC 2010, SC

There is a packet injection and monitoring utility called nemesis. 
This was available in the ports collection and I installed it.

Tue Feb 16 15:58:25 UTC 2010

I am stymied by the direct kernel patching stuff. I am working
through kong's book. And there is a point at which he mentions
that the trap.c code's syscall function should be patched if
we want to Trojan the sysent table.

I understand the basics, but when I try to write to the syscall
addresses I trigger a kernel panic. 

Why is that? I am unable to figure this out : yet !!

Wed Feb 17 22:06:09 UTC 2010

The panic is triggered  because the kernel core code is
changed. If I write the same bytes on top of a routine
such as syscall nothing happens. When even one byte is
changed panic attack happens. This leads me to think
there is some type of security check which prevents the
bytes from being modified. 

System calls can be modified but not the core os functions:
this is what I infer.

Kong's point about cloning the sysent table and then patching
syscall() to point to the new sysent doesnt seem possible with
the current FreeBSD version. It seems to be possible in earlier
versions. There appears to be some kind of digest check.

Thu Feb 18 09:25:48 UTC 2010

I found later that I could change single byte values. So it doesnt
seem to be a security or hash issue. The only reason I can think
of is that syscall code is probably continually exercised by
several threads and as the code is patched it is immediately 
executed by those threads. And if I write some invalid bytes
then the effect is immediate. So maybe the answer is to lock
and then write and release the lock .That would prevent other
threads from interfering?

But the kvm_write itself relies on the write system call and that
in turn will exercise the syscall routine. So does that cause
any problems? If I apply a lock will that cause some kind of
deadlock situation.

Mon Feb 22 19:10:13 UTC 2010

OK: none of the above were correct conjectures. It is possible
to patch any part of the kernel. After all that is how Binary
patches work. The problem I was facing was because of a silly
careless mistake: I had not patched all the Call statements.

And I was right about the syscall cod being exercised continuously.
As soon as I code the jump the code is executed and because of the
patch situation it bombed. 

Once I patched all the calls it worked like a breeze.

I also patched the sysent table address and was thus able to 
sucessfully trojan the syscall table. Again offsets and patches
have to be adjusted but it is all there in the copysysent.c
program.

The thing is: after the trojan is created the system works
with the trojan table. Any attempts to kldload a syscall
will only affect the original table (which is not used by the
system) and the trojan will remain unscathed. Thus it is a good
defensive technique against rootkits.

Probably I should write this up some place: Kong's book leaves
this as a coding exercise. 

Thu Feb 25 09:13:48 UTC 2010

OK, so I need to write up a kernel loadable module that will
not be a system call but will do some work on behalf of 
a user process in kernel land. So this will have to be a
pseudo device and the module will define the driver for the
device. That seems to be the way to do this. 

So I will rewrite the sysentreplace.c, which is currently a 
system call as the module. 

Fri Feb 26 11:19:50 UTC 2010

Actually that is easier said than done. I couldnt figure out
the clear cut difference between a system call and a module. 
I guess a system call is also implemented as a kernel loadable
module. But then how is a module that is not a system call, invoked?
I can understand the device driver concept. Perhaps that is how
all modules can be invoked. The kernel can be extended using the
modules for adding device drivers. I think the real answer lies
in figuring out the interrupt servicing process. A module is invoked
in response to an interrupt. So how are ISR registered? An ISR is
our module and so by registering it somewhere we can invoke it 
from userland through an interrupt. 

Sun Mar 14 00:13:18 UTC 2010

Well water has flown under the bridge since then. I now know how
to invoke the module logic from another module. Essentially it is
nothing but passing an event to the module and invoking its event
handler. There is the ability to register one event handler for
a module and that will have this giant switch statement that can
route control to other methods within the module. This is very 
similar to the event handling loop found in windowing environments. 

There is a module_t type which is a pointer to a module struct. 
Module lookup can be done (details are in the modcalltest and kldhide
programs) through the module_lookupbyname routine which returns
the pointer to the module struct corresponding to that module. 

The module struct has the pointer to the module's event handler code
which can then be invoked through that pointer. We cant use modfind
for this, because that returns only a modid which as far as my 
present knowledge goes cannot be used to invoke the event handler.


Actually one more wrinkle is that I am not able to call the module
from userland, the event can only be passed from another module. 
But that is ok: I can have one controller module whose job is to 
shoot events at others. The only issue is that this controller
module will have to be reloaded often when it is necessary to pass
events. But then userland programs will have to be recompiled also -
so it is not a total loss.

Wed Mar 17 15:44:00 UTC 2010

Meanwhile I finished most of the chapters in the Kong book. 

I installed tripwire (HIDS) from the ports collection. It seems
to be mucking around with the file system (that is ridiculous!!)
but I did get some kernel panic situation and a file system
problem during bootup. 

Thu Mar 18 18:59:19 UTC 2010

Now there are atleast three exercises in Kong's book which I can 
attempt. One of them has to do with writing a network trigger
and cloaking system calls, the second is to write a hook in 
mi_switch and capture context switches to figure out which processes
are being run, and the third is to iterate through the UMA Zone for
processes to figure out which proc structs have been removed
from the allproclist. The last two are defensive techniques whereas
the first one is a rootkit. 

Fri Mar 19 13:12:48 UTC 2010

I am going to do the mi_switch hook to see how that defensive technique
works. The system could crash.

Tue Mar 23 00:55:16 UTC 2010

I wrote up the mi_switch hook. It works. I am able to get the list
of procids on the system including the ones that are cloaked using
processhiding syscall. 

The mi_switchhook.c code contains the hook. This is a userland program.
Once this is run, the main console will be filled with the print out
statements. So it is best to run this in the secondary console
so that the address printed out can be seen.

The address is used by the uninstall routine to cancel out the hook.

ps -aex will give all the processes that are displayed by the mi_switchhook.
ps -ae will not give those processes which are daemons.

Fri Mar 26 17:59:12 UTC 2010


To eliminate the irritating warning treated as error problem
run make -DWERROR
that should take care of things.

Wed Mar 31 02:43:26 UTC 2010

Today I wrote up the UMA Zone iterator. This was mentioned as an exercise
in Kong's book. This is another way of getting at all running procs
in the system. I have given more detailed descriptions of how this is
achieved in the zoneiterate.c code.

With this I think I will put Kong's book to rest. 

There is a good Phrack article in issue 67 which describes the UMA Allocator
in some detail. I had to refer to the Phrack issue to get a basic           
understanding of how the Slab allocator works. Ironic isnt it? 
