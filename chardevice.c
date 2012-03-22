#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/uio.h>

// This here is the code for a character device. It allows the user
// to perform the open,close, read, and write operations.
// It will do the very useful task of copying user supplied data
// into an internal buffer.   

// The d_open_t is a function prototype defined in conf.h. 
//  So are all of the remaining ones as well. 

d_open_t open;
d_close_t close;
d_read_t read;
d_write_t write;

// Every device is described by the entries in the following struct.
// The initialization technique below is instructive, the dot notation
// is used for initializing only selected entries in the struct.
// d_name is the name by which the device is referred in the /dev folder
// and in the open calls etc.

static struct cdevsw cd_example_cdevsw = {

	.d_version = D_VERSION,
	.d_open = open,
	.d_close = close,
	.d_read = read,
	.d_write = write,
	.d_name = "cd_example"
};

static char buf[512+1];
static size_t len;

// Here the different operations are implemented. The interface
// conforms to the prototype defined.

// We can have whatever code we want in here. For example, the code
// here doesnt really open anything: it only initializes the buffer.
// This device allows the user to copy some data into a kernel
// buffer.

int open(struct cdev *dev, int flag, int otyp, struct thread* td) {

	memset(&buf, '\0', 513);
	len = 0;

	return 0;
}

int close(struct cdev *dev, int flag, int otyp, struct thread* td) {

	return 0;
}

//  You could call write without open, but then the issue is that
// we will be placing data into an uninitialized buffer.

int write(struct cdev *dev, struct uio* uio, int ioflag) {
	int error = 0;

// The copyinstr is one of the mechanisms by which userland data
// can be copied into the kernel data structure.

	error = copyinstr(uio->uio_iov->iov_base, &buf, 512, &len);

	if (error != 0) {

		uprintf("Write failed ho ho \n");
	}

	return(error);
}

int read(struct cdev *dev, struct uio * uio, int ioflag) {

	int error = 0;

	if (len <= 0) {

		error = -1;
	}

// Down below the copy does the transfer in the reverse direction.
	else {
		copystr(&buf, uio->uio_iov->iov_base, 513, &len);
	}

	return(error);
}

static struct cdev *sdev;

static int load(struct module* module, int cmd, void * args) {

	int error = 0;

	switch(cmd) {

		case MOD_LOAD:
// Here is the call to create the device under the /dev folder.
			sdev = make_dev(&cd_example_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "cd_example");
			uprintf("Character device loaded\n");
			break;
		case MOD_UNLOAD:
			destroy_dev(sdev);
			uprintf("Character device unloaded\n");
			break;

		default:
			error = EOPNOTSUPP;
			break;
	}

	return(error);
}

// Finally the declaration to the kernel that we have a device ready.
DEV_MODULE(cd_example, load, NULL);



	  
