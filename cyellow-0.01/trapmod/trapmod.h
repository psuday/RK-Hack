

#ifndef _TRAPMOD_H
#define _TRAPMOD_H

/* taken from /sys/kern/kern_module.c */
typedef TAILQ_HEAD(, module) modulelist_t;
struct module {
    TAILQ_ENTRY(module) link;           /* chain together all modules */
    TAILQ_ENTRY(module) flink;          /* all modules in a file */
    struct linker_file* file;           /* file which contains this module */
    int                 refs;           /* reference count */
    int                 id;             /* unique id number */
    char                *name;          /* module name */
    modeventhand_t      handler;        /* event handler */
    void                *arg;           /* argument for handler */
    modspecific_t       data;           /* module specific data */
};

extern linker_file_list_t linker_files;
extern int next_file_id;
extern modulelist_t modules;
extern int nextid;


int trapmod(struct proc *, struct kldload_args *);

#endif /* _SYMTABLE_H */
