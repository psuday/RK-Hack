// Well this program fleshes out another exercise that was given in 
// Kong's book. So what this is: every proc in the system needs to
// have a proc struct that is linked into the allproc list. This proc  
// struct is malloc'd and the memory is allocated from a slab. 
// BSD has a slab allocator. A Slab is a chunk of pre-allocated
// memory that contains items of a similar type. 
//
// So if we get to those structs directly and iterate through them
// we can figure out the true set of procs in the system. This is useful
// if a processhiding rootkit knocks off certain proc structs from the
// allproc list. 

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/uma_int.h>

// The mutex below is for locking the memory data structs before 
// iterating through them.

extern struct mtx uma_mtx;
void zoneiterate(void);

// So the simple definition of the UMA slab allocator is as follows:
// There are different zones which are backed by kegs. The zones
// are the so-called front end whereas the kegs are the so-called
// backend layer of the vm system. 
// vmstat -z will give a listing of all the zones in the system and 
// associated statistics.
// The keg can have multiple zones associated with it, but usually it is
// just one to one. The keg has the actual memory slabs and the zone
// is the logical association of the slab of memory to a application
// data structure.
// Thus there is a zone called "PROC" which contains all proc related
// data structures. The proc struct is allocated in this zone.
// The zone has a set of buckets which are for caching data. 

// All kegs are connected together into a list. The List head is in the
// variable as shown below.
extern LIST_HEAD(,uma_keg) uma_kegs;


void zoneiterate() {

// Below are the keg, zone, slab, and proc pointers. The bucket list
// was not useful at all. 

	uma_keg_t keg;
	uma_zone_t zone;
	//uma_bucket_t bucket;
	uma_slab_t slab;
	struct proc * p;
	int i;

// First lock the mutex to guard all data structures.
	mtx_lock(&uma_mtx);
// We start with the outermost loop which iterates through all kegs.

	LIST_FOREACH(keg, &uma_kegs, uk_link) {
// Within a keg we want to iterate through all zones: usually this is one to
// one. The zone list head is in the keg struct.

		LIST_FOREACH(zone, &keg->uk_zones, uz_link) {
// We are only interested in a zone called PROC.
			if (!strcmp(zone->uz_name, "PROC")) {
// And when we do get that zone, we just grab the slab lists from the 
// corresponding keg. There are three lists of slabs in the keg, partial,
// full, and free. Obviously we want only the partial and full slabs.
//    First the full slab, for no particular reason. 
				LIST_FOREACH(slab, &keg->uk_full_slab, us_link) {
				
// In each slab the structure is : there will be a slab header followed by
// items in the slab. The slab of memory is usually of page size.
// In the above iteration for slabs, we actually get the slab headers.
// Each slab header contains the pointer to the first item in the slab.
// And that pointer is us_data.
// Each keg contains a uk_ipers variable which contains the no of items
// in the slab.
// So our logic is to grab the us_data pointer value and assign it to
// a proc struct pointer. Then we iterate uk_ipers times to go through
// all items in the slab. We check the pid value, because it is possible
// that for a part slab there could be a junk value sitting there. 


						p=(struct proc *)slab->us_data;
						for (i = 0; i < keg->uk_ipers; i++) {
							if (p->p_pid > 0)
							uprintf("pid :%d name:%s\n", p->p_pid, p->p_comm);
							p++;
						}
						uprintf("Finished a slab\n");

				} 
// Now the part slab is processed.
				LIST_FOREACH(slab, &keg->uk_part_slab, us_link) {
				
						p=(struct proc *)slab->us_data;
						for (i = 0; i < keg->uk_ipers; i++) {
							if (p->p_pid > 0)
							uprintf("pid :%d name:%s\n", p->p_pid, p->p_comm);
							p++;
						}
						uprintf("Finished a slab\n");

				} 
				break;
			}
		}
	}
// Finally unlock the mutex.
	mtx_unlock(&uma_mtx);
}

// So when this module is loaded it will display all the procs in the
// part and full slabs, - mainly the pid and name. This can be correlated
// with the output of ps -aex. When the processhiding rootkit is run
// to knock off a proc struct from allproc list: it will disappear from
// the ps -aex output. But the listing from this module will show it still.
	
static int load(struct module * module, int cmd, void * args) {

	int error = 0;
	switch(cmd) {
		case MOD_LOAD:
			zoneiterate();
			break;
		case MOD_UNLOAD:
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}	

	return(error);
}

static moduledata_t zoneiterate_dat = {

	"zoneiterate",
	load,
	NULL
};

DECLARE_MODULE(zoneiterate, zoneiterate_dat, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);


