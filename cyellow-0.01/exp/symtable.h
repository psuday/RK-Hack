

#ifndef _SYMTABLE_H
#define _SYMTABLE_H

struct set_symbol_args {
    u_int32_t address;
    char *name;
};

int set_symbol(struct proc *, struct set_symbol_args *);

/* taken from /sys/kern/link_elf.c */

typedef struct elf_file {
    caddr_t             address;        /* Relocation address */
#ifdef SPARSE_MAPPING
    vm_object_t         object;         /* VM object to hold file pages */
#endif
    const Elf_Dyn*      dynamic;        /* Symbol table etc. */
    Elf_Off             nbuckets;       /* DT_HASH info */
    Elf_Off             nchains;
    const Elf_Off*      buckets;
    const Elf_Off*      chains;
    caddr_t             hash;
    caddr_t             strtab;         /* DT_STRTAB */
    int                 strsz;          /* DT_STRSZ */
    const Elf_Sym*      symtab;         /* DT_SYMTAB */
    Elf_Addr*           got;            /* DT_PLTGOT */
    const Elf_Rel*      pltrel;         /* DT_JMPREL */
    int                 pltrelsize;     /* DT_PLTRELSZ */
    const Elf_Rela*     pltrela;        /* DT_JMPREL */
    int                 pltrelasize;    /* DT_PLTRELSZ */
    const Elf_Rel*      rel;            /* DT_REL */
    int                 relsize;        /* DT_RELSZ */
    const Elf_Rela*     rela;           /* DT_RELA */
    int                 relasize;       /* DT_RELASZ */
    caddr_t             modptr;
    const Elf_Sym*      ddbsymtab;      /* The symbol table we are using */
    long                ddbsymcnt;      /* Number of symbols */
    caddr_t             ddbstrtab;      /* String table */
    long                ddbstrcnt;      /* number of bytes in string table */
    caddr_t             symbase;        /* malloc'ed symbold base */
    caddr_t             strbase;        /* malloc'ed string base */
} *elf_file_t;



#endif /* _SYMTABLE_H */
