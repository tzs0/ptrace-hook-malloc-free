#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <regex.h>
#include <setjmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>
#include <link.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>


typedef void* (*FUNC_PROXY)(void*);

typedef struct _elf_info {
	const char* pathname;

	ElfW(Addr)  base_addr;
	ElfW(Addr)  bias_addr;

	ElfW(Ehdr)* ehdr;
	ElfW(Phdr)* phdr;

	ElfW(Dyn)*  dyn;   //.dynamic
	ElfW(Word)  dyn_sz;

	const char* strtab; //.dynstr (string-table)
	ElfW(Sym)*  symtab;   //.dynsym (symbol-index to string-table's offset)

	ElfW(Addr)  relplt;   //.rel.plt or .rela.plt
	ElfW(Word)  relplt_sz;

	ElfW(Addr)  reldyn;   //.rel.dyn or .rela.dyn
	ElfW(Word)  reldyn_sz;

	ElfW(Addr)  relandroid;   //android compressed rel or rela
	ElfW(Word)  relandroid_sz;

	//for ELF hash
	uint32_t*   bucket;
	uint32_t    bucket_cnt;
	uint32_t*   chain;
	uint32_t    chain_cnt; //invalid for GNU hash

	//append for GNU hash
	uint32_t    symoffset;
	ElfW(Addr)* bloom;
	uint32_t    bloom_sz;
	uint32_t    bloom_shift;

	int         is_use_rela;
	int         is_use_gnu_hash;
} elf_info_t;

//iterator for plain PLT
typedef struct {
	uint8_t*  cur;
	uint8_t*  end;
	int       is_use_rela;
} elf_plain_reloc_iterator_t;

//sleb128 decoder
typedef struct {
	uint8_t*  cur;
	uint8_t*  end;
} elf_sleb128_decoder_t;

//iterator for sleb128 decoded packed PLT
typedef struct {
	elf_sleb128_decoder_t decoder;
	size_t                   relocation_count;
	size_t                   group_size;
	size_t                   group_flags;
	size_t                   group_r_offset_delta;
	size_t                   relocation_index;
	size_t                   relocation_group_index;
	ElfW(Rela)               rela;
	ElfW(Rel)                rel;
	ElfW(Addr)               r_offset;
	size_t                   r_info;
	ssize_t                  r_addend;
	int                      is_use_rela;
} elf_packed_reloc_iterator_t;

const size_t RELOCATION_GROUPED_BY_INFO_FLAG         = 1;
const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG       = 4;
const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG        = 8;

//#define         __arm__
//#define         __aarch64__
#define         __i386__
//#define         __x86_64__

//#if defined(__x86_64__) || defined(__aarch64__)
//#ifndef __LP64__
//    #define __LP64__
//#endif
//#define UTIL_FMT_LEN     "16"
//#define UTIL_FMT_X       "llx"
//#else
#define UTIL_FMT_LEN     "8"
#define UTIL_FMT_X       "x"
//#endif

#ifndef EI_ABIVERSION
#define EI_ABIVERSION 8
#endif

#if defined(__arm__)
#define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT      //.rel.plt
#define ELF_R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT       //.rel.dyn
#define ELF_R_GENERIC_ABS       R_ARM_ABS32          //.rel.dyn
#elif defined(__aarch64__)
#define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define ELF_R_GENERIC_ABS       R_AARCH64_ABS64
#elif defined(__i386__)
#define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define ELF_R_GENERIC_ABS       R_386_32
//#elif defined(__x86_64__)
//#define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
//#define ELF_R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
//#define ELF_R_GENERIC_ABS       R_X86_64_64
#endif

#if defined(__i386__) //defined(__x86_64__) || defined(__aarch64__)
#define ELF_R_SYM(info)  ELF32_R_SYM(info)
#define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#else
#define ELF_R_SYM(info)  ELF64_R_SYM(info)
#define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#endif

#define UTIL_FMT_FIXED_X UTIL_FMT_LEN UTIL_FMT_X
#define UTIL_FMT_FIXED_S UTIL_FMT_LEN "s"

#ifndef __MS
#define __MS(m)	#m
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)		\
	(sizeof(arr) / sizeof((arr)[0]))
#endif

#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr + sizeof(uintptr_t) - 1) + PAGE_SIZE)
#define PAGE_COVER(addr) (PAGE_END(addr) - PAGE_START(addr))

#define so_printf(fmt, ...) 		printf("[%s %d] "fmt, __func__, __LINE__, ##__VA_ARGS__)


static ElfW(Phdr)* elf_get_first_segment_by_type(elf_info_t* self, ElfW(Word) type);
static int elf_packed_reloc_iterator_read_group_fields(elf_packed_reloc_iterator_t* self);
static int elf_sleb128_decoder_next(elf_sleb128_decoder_t* self, size_t* ret);
static void elf_sleb128_decoder_init(elf_sleb128_decoder_t* self,
                                     ElfW(Addr) rel, ElfW(Word) rel_sz);
static int elf_replace_function(elf_info_t* self, const char* symbol, ElfW(Addr) addr, void* new_func, void** old_func);
static void* elf_packed_reloc_iterator_next(elf_packed_reloc_iterator_t* self);
static int elf_packed_reloc_iterator_init(elf_packed_reloc_iterator_t* self,
                                          ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela);
static int elf_find_and_replace_func(elf_info_t* self, const char* section,
                                     int is_plt, const char* symbol,
                                     void* new_func, void** old_func,
                                     uint32_t symidx, void* rel_common,
                                     int* found);
static void* elf_plain_reloc_iterator_next(elf_plain_reloc_iterator_t* self);
static void elf_plain_reloc_iterator_init(elf_plain_reloc_iterator_t* self,
                                          ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela);
static uint32_t elf_hash(const uint8_t* name);
static uint32_t elf_gnu_hash(const uint8_t* name);
static int elf_gnu_hash_lookup_undef(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab);
static int elf_gnu_hash_lookup_def(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab);
static int elf_gnu_hash_lookup(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab);
static int elf_hash_lookup(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab);
static int elf_find_symidx_by_name(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab);
static void elf_dump_symtab(elf_info_t* self);
static void elf_dump_rel(elf_info_t* self, const char* type, ElfW(Addr) rel_addr, ElfW(Word) rel_sz);
static void elf_dump_dynamic(elf_info_t* self);
static void elf_dump_programheader(elf_info_t* self);
static void elf_dump_elfheader(elf_info_t* self);
static void elf_dump(elf_info_t* self);
static uintptr_t get_elf_addr(int pid, char* elf_str);
static int check_elfheader(uintptr_t base_addr);
static int elf_init(elf_info_t* self, uintptr_t base_addr, const char* pathname);
static int elf_check(elf_info_t* self);
static int util_get_mem_protect(uintptr_t addr, size_t len, const char* pathname, unsigned int* prot);
static int util_get_addr_protect(uintptr_t addr, const char* pathname, unsigned int* prot);
static int util_set_addr_protect(uintptr_t addr, unsigned int prot);
static void util_flush_instruction_cache(uintptr_t addr);

static elf_info_t elf_info;

//void print_mystr() __attribute__((section (".mytext")));
//void lib_init( void ) __attribute__( ( constructor ) );



static int util_get_mem_protect(uintptr_t addr, size_t len, const char* pathname, unsigned int* prot)
{
	uintptr_t  start_addr = addr;
	uintptr_t  end_addr = addr + len;
	FILE*      fp;
	char       line[512];
	uintptr_t  start, end;
	char       perm[5];
	int        load0 = 1;
	int        found_all = 0;

	*prot = 0;

	if(NULL == (fp = fopen("/proc/self/maps", "r"))) {
		return -1;
	}

	while(fgets(line, sizeof(line), fp)) {
		if(NULL != pathname)
			if(NULL == strstr(line, pathname)) {
				continue;
			}

		if(sscanf(line, "%"PRIxPTR"-%"PRIxPTR" %4s ", &start, &end, perm) != 3) {
			continue;
		}

		if(perm[3] != 'p') {
			continue;
		}

		if(start_addr >= start && start_addr < end) {
			if(load0) {
				//first load segment
				if(perm[0] == 'r') {
					*prot |= PROT_READ;
				}
				if(perm[1] == 'w') {
					*prot |= PROT_WRITE;
				}
				if(perm[2] == 'x') {
					*prot |= PROT_EXEC;
				}
				load0 = 0;
			}
			else {
				//others
				if(perm[0] != 'r') {
					*prot &= ~PROT_READ;
				}
				if(perm[1] != 'w') {
					*prot &= ~PROT_WRITE;
				}
				if(perm[2] != 'x') {
					*prot &= ~PROT_EXEC;
				}
			}

			if(end_addr <= end) {
				found_all = 1;
				break; //finished
			}
			else {
				start_addr = end; //try to find the next load segment
			}
		}
	}

	fclose(fp);

	if(!found_all) {
		return -1;
	}

	return 0;
}

static int util_get_addr_protect(uintptr_t addr, const char* pathname, unsigned int* prot)
{
	return util_get_mem_protect(addr, sizeof(addr), pathname, prot);
}

static int util_set_addr_protect(uintptr_t addr, unsigned int prot)
{
	if(0 != mprotect((void*)PAGE_START(addr), PAGE_COVER(addr), (int)prot)) {
		return 0 == errno ? -1 : errno;
	}

	return 0;
}

static void util_flush_instruction_cache(uintptr_t addr)
{
	__builtin___clear_cache((void*)PAGE_START(addr), (void*)PAGE_END(addr));
}

static int check_elfheader(uintptr_t base_addr)
{
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)base_addr;

	//check magic
	if(0 != memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
		so_printf("check magic error \n");
		return -1;
	}

	//check class (64/32)
#if defined(__LP64__)
	if(ELFCLASS64 != ehdr->e_ident[EI_CLASS]) {
		so_printf("ehdr->e_ident[EI_CLASS](%d)!=ELFCLASS64(%d) \n", ehdr->e_ident[EI_CLASS], ELFCLASS64);
		return -1;
	}
#else
	if(ELFCLASS32 != ehdr->e_ident[EI_CLASS]) {
		so_printf("ehdr->e_ident[EI_CLASS](%d)!=ELFCLASS32(%d) \n", ehdr->e_ident[EI_CLASS], ELFCLASS32);
		return -1;
	}
#endif

	//check endian (little/big)
	if(ELFDATA2LSB != ehdr->e_ident[EI_DATA]) {
		so_printf("ehdr->e_ident[EI_DATA](%d)!=ELFDATA2LSB(%d)\n", ehdr->e_ident[EI_DATA],ELFDATA2LSB);
		return -1;
	}

	//check version
	if(EV_CURRENT != ehdr->e_ident[EI_VERSION]) {
		return -1;
	}

	//check type
	if(ET_EXEC != ehdr->e_type && ET_DYN != ehdr->e_type) {
		return -1;
	}

	//check machine
#if defined(__arm__)
	if(EM_ARM != ehdr->e_machine) {
		return -1;
	}
#elif defined(__aarch64__)
	if(EM_AARCH64 != ehdr->e_machine) {
		return -1;
	}
#elif defined(__i386__)
	if(EM_386 != ehdr->e_machine) {
		return -1;
	}
//#elif defined(__x86_64__)
//	if( EM_X86_64 != ehdr->e_machine ) {
//		return -1;
//	}
#else
	return -1;
#endif

	//check version
	if(EV_CURRENT != ehdr->e_version) {
		return -1;
	}

	so_printf("check_elfheader OK!\n");

	return 0;
}

static uintptr_t get_elf_addr(int pid, char* elf_str)
{
	uintptr_t ret = 0;
	char buf[4096], *temp;
	FILE* fp;

	if(pid<=0) {
		sprintf(buf, "/proc/%d/maps", getpid());
	}
	else {
		sprintf(buf, "/proc/%d/maps", pid);
	}

	fp = fopen(buf, "r");
	if(fp == NULL) {
		so_printf("open failed\n");
		goto _error;
	}
	while(fgets(buf, sizeof(buf), fp)) {
		if(strstr(buf, elf_str)) {
			temp = strtok(buf, "-");
			so_printf("addr:%s\n", temp);
			ret = strtoul(temp, NULL, 16);
			break;
		}
	}
_error:
	fclose(fp);
	return ret;
}

static ElfW(Phdr)* elf_get_first_segment_by_type_offset(elf_info_t* self, ElfW(Word) type, ElfW(Off) offset)
{
	ElfW(Phdr) *phdr;

	for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++) {
		if(phdr->p_type == type && phdr->p_offset == offset) {
			return phdr;
		}
	}
	return NULL;
}

static int elf_check(elf_info_t* self)
{
	if(0 == self->base_addr) {
		so_printf("error, base_addr == 0\n");
		return 1;
	}
	if(0 == self->bias_addr) {
		so_printf("error, bias_addr == 0\n");
//        return 1; /* if ASLR is disable, bias_addr maybe 0 */
	}
	if(NULL == self->ehdr) {
		so_printf("error, ehdr == NULL\n");
		return 1;
	}
	if(NULL == self->phdr) {
		so_printf("error, phdr == NULL\n");
		return 1;
	}
	if(NULL == self->strtab) {
		so_printf("error, strtab == NULL\n");
		return 1;
	}
	if(NULL == self->symtab) {
		so_printf("error, symtab == NULL\n");
		return 1;
	}
	if(NULL == self->bucket) {
		so_printf("error, bucket == NULL\n");
		return 1;
	}
	if(NULL == self->chain) {
		so_printf("error, chain == NULL\n");
		return 1;
	}
	if(1 == self->is_use_gnu_hash && NULL == self->bloom) {
		so_printf("error, bloom == NULL\n");
		return 1;
	}

	return 0;
}

static void elf_dump_programheader(elf_info_t* self)
{
	ElfW(Phdr) *phdr = self->phdr;
	size_t i;

	so_printf("Program Headers:\n");
	printf("  %-8s " \
	       "%-"UTIL_FMT_FIXED_S" " \
	       "%-"UTIL_FMT_FIXED_S" " \
	       "%-"UTIL_FMT_FIXED_S" " \
	       "%-"UTIL_FMT_FIXED_S" " \
	       "%-"UTIL_FMT_FIXED_S" " \
	       "%-8s " \
	       "%-s\n",
	       "Type",
	       "Offset",
	       "VirtAddr",
	       "PhysAddr",
	       "FileSiz",
	       "MemSiz",
	       "Flg",
	       "Align");
	for(i = 0; i < self->ehdr->e_phnum; i++, phdr++) {
		printf("  %-8x " \
		       "%."UTIL_FMT_FIXED_X" " \
		       "%."UTIL_FMT_FIXED_X" " \
		       "%."UTIL_FMT_FIXED_X" " \
		       "%."UTIL_FMT_FIXED_X" " \
		       "%."UTIL_FMT_FIXED_X" " \
		       "%-8x " \
		       "%"UTIL_FMT_X"\n",
		       phdr->p_type,
		       phdr->p_offset,
		       phdr->p_vaddr,
		       phdr->p_paddr,
		       phdr->p_filesz,
		       phdr->p_memsz,
		       phdr->p_flags,
		       phdr->p_align);
	}
}

static void elf_dump_elfheader(elf_info_t* self)
{
	static char alpha_tab[17] = "0123456789ABCDEF";
	int         i;
	uint8_t     ch;
	char        buff[EI_NIDENT * 3 + 1];

	for(i = 0; i < EI_NIDENT; i++) {
		ch = self->ehdr->e_ident[i];
		buff[i * 3 + 0] = alpha_tab[(int)((ch >> 4) & 0x0F)];
		buff[i * 3 + 1] = alpha_tab[(int)(ch & 0x0F)];
		buff[i * 3 + 2] = ' ';
	}
	buff[EI_NIDENT * 3] = '\0';

	printf("Elf Header:\n");
	printf("  Magic:                             %s\n",                                 buff);
	printf("  Class:                             %#x\n",                                self->ehdr->e_ident[EI_CLASS]);
	printf("  Data:                              %#x\n",                                self->ehdr->e_ident[EI_DATA]);
	printf("  Version:                           %#x\n",                                self->ehdr->e_ident[EI_VERSION]);
	printf("  OS/ABI:                            %#x\n",                                self->ehdr->e_ident[EI_OSABI]);
	printf("  ABI Version:                       %#x\n",                                self->ehdr->e_ident[EI_ABIVERSION]);
	printf("  Type:                              %#x\n",                                self->ehdr->e_type);
	printf("  Machine:                           %#x\n",                                self->ehdr->e_machine);
	printf("  Version:                           %#x\n",                                self->ehdr->e_version);
	printf("  Entry point address:               %"UTIL_FMT_X"\n",                   self->ehdr->e_entry);
	printf("  Start of program headers:          %"UTIL_FMT_X" (bytes into file)\n", self->ehdr->e_phoff);
	printf("  Start of section headers:          %"UTIL_FMT_X" (bytes into file)\n", self->ehdr->e_shoff);
	printf("  Flags:                             %#x\n",                                self->ehdr->e_flags);
	printf("  Size of this header:               %u (bytes)\n",                         self->ehdr->e_ehsize);
	printf("  Size of program headers:           %u (bytes)\n",                         self->ehdr->e_phentsize);
	printf("  Number of program headers:         %u\n",                                 self->ehdr->e_phnum);
	printf("  Size of section headers:           %u (bytes)\n",                         self->ehdr->e_shentsize);
	printf("  Number of section headers:         %u\n",                                 self->ehdr->e_shnum);
	printf("  Section header string table index: %u\n",                                 self->ehdr->e_shstrndx);
}

static void elf_dump_dynamic(elf_info_t* self)
{
	ElfW(Dyn) *dyn = self->dyn;
	size_t     dyn_cnt = (self->dyn_sz / sizeof(ElfW(Dyn)));
	size_t     i;

	so_printf("Dynamic section contains %zu entries:\n", dyn_cnt);
	printf("  %-"UTIL_FMT_FIXED_S" " \
	       "%s\n",
	       "Tag",
	       "Val");
	for(i = 0; i < dyn_cnt; i++, dyn++) {
		printf("  %-"UTIL_FMT_FIXED_X" " \
		       "%-"UTIL_FMT_X"\n",
		       dyn->d_tag,
		       dyn->d_un.d_val);
	}
}

static void elf_dump_rel(elf_info_t* self, const char* type, ElfW(Addr) rel_addr, ElfW(Word) rel_sz)
{
	ElfW(Rela) *rela;
	ElfW(Rel)  *rel;
	ElfW(Word)  cnt;
	ElfW(Word)  i;
	ElfW(Sym)  *sym;

	if(self->is_use_rela) {
		rela = (ElfW(Rela)*)(rel_addr);
		cnt  = rel_sz / sizeof(ElfW(Rela));
	}
	else {
		rel = (ElfW(Rel)*)(rel_addr);
		cnt = rel_sz / sizeof(ElfW(Rel));
	}

	so_printf("Relocation section '.rel%s%s' contains %u entries:\n",
	            (self->is_use_rela ? "a" : ""), type, cnt);
	printf("  %-"UTIL_FMT_FIXED_S" " \
	       "%-"UTIL_FMT_FIXED_S" " \
	       "%-8s " \
	       "%-8s " \
	       "%-8s " \
	       "%s\n",
	       "Offset",
	       "Info",
	       "Type",
	       "Sym.Idx",
	       "Sym.Val",
	       "Sym.Name");
	const char* fmt = "  %."UTIL_FMT_FIXED_X" " \
	                  "%."UTIL_FMT_FIXED_X" " \
	                  "%.8x " \
	                  "%.8u " \
	                  "%.8x " \
	                  "%s\n";
	for(i = 0; i < cnt; i++) {
		if(self->is_use_rela) {
			sym = &(self->symtab[ELF_R_SYM(rela[i].r_info)]);
			printf(fmt,
			       rela[i].r_offset,
			       rela[i].r_info,
			       ELF_R_TYPE(rela[i].r_info),
			       ELF_R_SYM(rela[i].r_info),
			       sym->st_value,
			       self->strtab + sym->st_name);
		}
		else {
			sym = &(self->symtab[ELF_R_SYM(rel[i].r_info)]);
			printf(fmt,
			       rel[i].r_offset,
			       rel[i].r_info,
			       ELF_R_TYPE(rel[i].r_info),
			       ELF_R_SYM(rel[i].r_info),
			       sym->st_value,
			       self->strtab + sym->st_name);
		}
	}
}

static void elf_dump_symtab(elf_info_t* self)
{
	if(self->is_use_gnu_hash) {
		return;
	}

	ElfW(Word)  symtab_cnt = self->chain_cnt;
	ElfW(Word)  i;

	so_printf("Symbol table '.dynsym' contains %u entries:\n", symtab_cnt);
	printf("  %-8s " \
	       "%-"UTIL_FMT_FIXED_S" " \
	       "%s\n",
	       "Idx",
	       "Value",
	       "Name");
	for(i = 0; i < symtab_cnt; i++) {
		printf("  %-8u " \
		       "%."UTIL_FMT_FIXED_X" " \
		       "%s\n",
		       i,
		       self->symtab[i].st_value,
		       self->strtab + self->symtab[i].st_name);
	}
}

static void elf_dump(elf_info_t* self)
{
//    if(log_priority < ANDROID_LOG_DEBUG) return;

	so_printf("Elf Pathname: %s\n", self->pathname);
	so_printf("Elf bias addr: %p\n", (void*)self->bias_addr);
	elf_dump_elfheader(self);
	elf_dump_programheader(self);
	elf_dump_dynamic(self);
	elf_dump_rel(self, ".plt", self->relplt, self->relplt_sz);
	elf_dump_rel(self, ".dyn", self->reldyn, self->reldyn_sz);
	elf_dump_symtab(self);
}

static ElfW(Phdr)* elf_get_first_segment_by_type(elf_info_t* self, ElfW(Word) type)
{
	ElfW(Phdr) *phdr;

	for(phdr = self->phdr; phdr < self->phdr + self->ehdr->e_phnum; phdr++) {
		if(phdr->p_type == type) {
			return phdr;
		}
	}
	return NULL;
}

static int elf_init(elf_info_t* self, uintptr_t base_addr, const char* pathname)
{
	if(0 == base_addr || NULL == pathname) {
		return -1;
	}

	//always reset
	memset(self, 0, sizeof(elf_info_t));

	self->pathname = pathname;
	self->base_addr = (ElfW(Addr))base_addr;
	self->ehdr = (ElfW(Ehdr)*)base_addr;
	self->phdr = (ElfW(Phdr)*)(base_addr + self->ehdr->e_phoff);       //segmentation fault sometimes

	//find the first load-segment with offset 0
	ElfW(Phdr) *phdr0 = elf_get_first_segment_by_type_offset(self, PT_LOAD, 0);
	if(NULL == phdr0) {
		so_printf("Can NOT found the first load segment. %s\n", pathname);
		return -1;
	}

#if ELF_DEBUG
	if(0 != phdr0->p_vaddr)
		so_printf("first load-segment vaddr NOT 0 (vaddr: %p). %s\n",
		            (void*)(phdr0->p_vaddr), pathname);
	else {
		so_printf("phdr0->p_vaddr is 0\n");
	}
#endif

	so_printf("self->base_addr:%#x phdr0->p_vaddr:%p\n", self->base_addr, phdr0->p_vaddr);
	//save load bias addr
	if(self->base_addr < phdr0->p_vaddr) {
		so_printf("error, self->base_addr(%d)<phdr0->p_vaddr(%d)", self->base_addr, phdr0->p_vaddr);
		return -1;
	}

	self->bias_addr = self->base_addr - phdr0->p_vaddr;
	so_printf("self->bias_addr：%#x \n", self->bias_addr);

	//find dynamic-segment
	ElfW(Phdr) *dhdr = elf_get_first_segment_by_type(self, PT_DYNAMIC);
	if(NULL == dhdr) {
		so_printf("Can NOT found dynamic segment. %s\n", pathname);
		return -1;
	}
	so_printf("PT_DYNAMIC:%d dhdr:%p dhdr->p_vaddr:%#x\n", PT_DYNAMIC, dhdr, dhdr->p_vaddr);

	//parse dynamic-segment
	self->dyn          = (ElfW(Dyn)*)(self->bias_addr + dhdr->p_vaddr);
	so_printf("self->dyn:%#x\n", self->dyn);
	self->dyn_sz       = dhdr->p_memsz;
	so_printf("self->dyn_sz:%d\n", self->dyn_sz);
	ElfW(Dyn) *dyn     = self->dyn;
	so_printf("dyn:%p\n", dyn);

	ElfW(Dyn) *dyn_end = self->dyn + (self->dyn_sz / sizeof(ElfW(Dyn)));
	so_printf("( self->dyn_sz / sizeof( ElfW( Dyn ) ) ):%d dyn_end:%p\n",
	            (self->dyn_sz / sizeof(ElfW(Dyn))),dyn_end);
	uint32_t*  raw;
	for(; dyn < dyn_end; dyn++) {
		if(dyn->d_tag>DT_NUM) {
			so_printf("dyn:%p dyn->d_tag:%#x\n", dyn, dyn->d_tag);
		}
		else {
			so_printf("dyn:%p dyn->d_tag:%d\n", dyn, dyn->d_tag);
		}
		switch(dyn->d_tag) {   //segmentation fault sometimes
			case DT_NULL:
				//the end of the dynamic-section
				dyn = dyn_end;
				break;
			case DT_STRTAB: {
				so_printf("DT_STRTAB:%d\n", DT_STRTAB);
				so_printf("bias_addr:%p dyn->d_un.d_ptr:%p\n",self->bias_addr,dyn->d_un.d_ptr);
//				self->strtab = ( const char* )( self->bias_addr + dyn->d_un.d_ptr );
				self->strtab = (const char*)(dyn->d_un.d_ptr);
				so_printf("strtab:%s\n", self->strtab);
				if((ElfW(Addr))(self->strtab) < self->base_addr) {
					so_printf("error, ( ElfW( Addr ) )( self->strtab )(%d)<self->base_addr(%d)\n",
					            (ElfW(Addr))(self->strtab), self->base_addr);
					return -1;
				}
				break;
			}
			case DT_SYMTAB: {
				so_printf("DT_SYMTAB:%d\n", DT_SYMTAB);
				so_printf("bias_addr:%p dyn->d_un.d_ptr:%p\n",self->bias_addr,dyn->d_un.d_ptr);
//				self->symtab = ( ElfW( Sym )* )( self->bias_addr + dyn->d_un.d_ptr );
				self->symtab = (ElfW(Sym)*)(dyn->d_un.d_ptr);
				if((ElfW(Addr))(self->symtab) < self->base_addr) {
					so_printf("error, ( ElfW( Addr ) )( self->symtab )(%d)<self->base_addr(%d)\n",
					            (ElfW(Addr))(self->symtab), self->base_addr);
					return -1;
				}
				break;
			}
			case DT_PLTREL:
				//use rel or rela?
				self->is_use_rela = (dyn->d_un.d_val == DT_RELA ? 1 : 0);
				break;
			case DT_JMPREL: {
				so_printf("DT_JMPREL:%d\n", DT_JMPREL);
				so_printf("bias_addr:%p dyn->d_un.d_ptr:%p\n",self->bias_addr,dyn->d_un.d_ptr);

//				self->relplt = ( ElfW( Addr ) )( self->bias_addr + dyn->d_un.d_ptr );
				self->relplt = (ElfW(Addr))(dyn->d_un.d_ptr);
				so_printf("self->relplt:%p\n", self->relplt);

				if((ElfW(Addr))(self->relplt) < self->base_addr) {
					so_printf("error, ( ElfW( Addr ) )( self->relplt )(%d)<self->base_addr(%d)\n",
					            (ElfW(Addr))(self->relplt), self->base_addr);
					return -1;
				}
				break;
			}
			case DT_PLTRELSZ:
				self->relplt_sz = dyn->d_un.d_val;
				so_printf("self->relplt_sz:%d\n", self->relplt_sz);
				break;
			case DT_REL:
				so_printf("DT_REL:%d\n", DT_REL);
			case DT_RELA: {
				so_printf("DT_RELA:%d\n", DT_RELA);
				so_printf("DT_RELA bias_addr:%p dyn->d_un.d_ptr:%p\n",self->bias_addr,dyn->d_un.d_ptr);
//				self->reldyn = ( ElfW( Addr ) )( self->bias_addr + dyn->d_un.d_ptr );
				self->reldyn = (ElfW(Addr))(dyn->d_un.d_ptr);
				if((ElfW(Addr))(self->reldyn) < self->base_addr) {
					so_printf("error, ( ElfW( Addr ) )( self->reldyn )(%d)<self->base_addr(%d)\n",
					            (ElfW(Addr))(self->reldyn), self->base_addr);
					return -1;
				}
				break;
			}
			case DT_RELSZ:
			case DT_RELASZ:
				self->reldyn_sz = dyn->d_un.d_val;
				break;
#if 0
			case DT_ANDROID_REL:
			case DT_ANDROID_RELA: {
				self->relandroid = (ElfW(Addr))(self->bias_addr + dyn->d_un.d_ptr);
				if((ElfW(Addr))(self->relandroid) < self->base_addr) {
					so_printf("error, ( ElfW( Addr ) )( self->relandroid )(%d)<self->base_addr(%d)\n",
					            (ElfW(Addr))(self->relandroid), self->base_addr);
					return -1;
				}
				break;
			}
			case DT_ANDROID_RELSZ:
			case DT_ANDROID_RELASZ:
				self->relandroid_sz = dyn->d_un.d_val;
				break;
#endif
			case DT_HASH: {
				so_printf("DT_HASH:%d\n", DT_HASH);
				//ignore DT_HASH when ELF contains DT_GNU_HASH hash table
				if(1 == self->is_use_gnu_hash) {
					continue;
				}
				so_printf("DT_HASH bias_addr:%p dyn->d_un.d_ptr:%p\n",self->bias_addr,dyn->d_un.d_ptr);
//				raw = ( uint32_t* )( self->bias_addr + dyn->d_un.d_ptr );
				raw = (uint32_t*)(dyn->d_un.d_ptr);
				if((ElfW(Addr))raw < self->base_addr) {
					so_printf("error, ( ElfW( Addr ) )raw(%d)<self->base_addr(%d)\n",
					            (ElfW(Addr))raw, self->base_addr);
					return -1;
				}
				self->bucket_cnt  = raw[0];
				self->chain_cnt   = raw[1];
				self->bucket      = &raw[2];
				self->chain       = &(self->bucket[self->bucket_cnt]);
				break;
			}
			case DT_GNU_HASH: {
				so_printf("DT_GNU_HASH:%d bias_addr:%p dyn->d_un.d_ptr:%p\n",
				            DT_GNU_HASH, self->bias_addr, dyn->d_un.d_ptr);
//				raw = ( uint32_t* )( self->bias_addr + dyn->d_un.d_ptr );
				raw = (uint32_t*)(dyn->d_un.d_ptr);
				if((ElfW(Addr))raw < self->base_addr) {
					so_printf("error, ( ElfW( Addr ) )raw(%d)<self->base_addr(%d)\n",
					            (ElfW(Addr))raw, self->base_addr);
					return -1;
				}
				self->bucket_cnt  = raw[0];
				self->symoffset   = raw[1];
				self->bloom_sz    = raw[2];
				self->bloom_shift = raw[3];
				self->bloom       = (ElfW(Addr)*)(&raw[4]);
				self->bucket      = (uint32_t*)(&(self->bloom[self->bloom_sz]));
				self->chain       = (uint32_t*)(&(self->bucket[self->bucket_cnt]));
				self->is_use_gnu_hash = 1;
				break;
			}
			default:
				break;
		}
	}

	//check android rel/rela
	if(0 != self->relandroid) {
		const char* rel = (const char*)self->relandroid;
		if(self->relandroid_sz < 4 ||
		   rel[0] != 'A' ||
		   rel[1] != 'P' ||
		   rel[2] != 'S' ||
		   rel[3] != '2') {
			so_printf("android rel/rela format error\n");
			return -1;
		}

		self->relandroid += 4;
		self->relandroid_sz -= 4;
	}

	//check elf info
	if(0 != elf_check(self)) {
		so_printf("elf init check failed. pathname:%s\n", pathname);
		return -1;
	}

#if ELF_DEBUG
	elf_dump(self);
#endif

	so_printf("init OK: %s (%s %s PLT:%u DYN:%u ANDROID:%u)\n", self->pathname,
	            self->is_use_rela ? "RELA" : "REL",
	            self->is_use_gnu_hash ? "GNU_HASH" : "ELF_HASH",
	            self->relplt_sz, self->reldyn_sz, self->relandroid_sz);

	return 0;
}

static int elf_hash_lookup(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab)
{
	uint32_t    hash = elf_hash((uint8_t*)symbol);
	const char* symbol_cur;
	uint32_t    i;

	for(i = self->bucket[hash % self->bucket_cnt]; 0 != i; i = self->chain[i]) {
		symbol_cur = self->strtab + self->symtab[i].st_name;

		if(0 == strcmp(symbol, symbol_cur)) {
			*symidx = i;
			*symtab = &(self->symtab[i]); /* 找个这个函数的符号表 */
			so_printf("found %s at symidx: %u (ELF_HASH) symtab：%p\n", symbol, *symidx, *symtab);
			return 0;
		}
	}

	so_printf("dont find\n");
	return -1;
}

static uint32_t elf_gnu_hash(const uint8_t* name)
{
	uint32_t h = 5381;

	while(*name != 0) {
		h += (h << 5) + *name++;
	}
	return h;
}

static uint32_t elf_hash(const uint8_t* name)
{
	uint32_t h = 0, g;

	while(*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}

	return h;
}

static int elf_gnu_hash_lookup_def(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab)
{
	uint32_t hash = elf_gnu_hash((uint8_t*)symbol);

	static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
	size_t word = self->bloom[(hash / elfclass_bits) % self->bloom_sz];
	size_t mask = 0
	              | (size_t)1 << (hash % elfclass_bits)
	              | (size_t)1 << ((hash >> self->bloom_shift) % elfclass_bits);

	//if at least one bit is not set, this symbol is surely missing
	if((word & mask) != mask) {
		return -1;
	}

	//ignore STN_UNDEF
	uint32_t i = self->bucket[hash % self->bucket_cnt];
	if(i < self->symoffset) {
		return -1;
	}

	//loop through the chain
	while(1) {
		const char*     symname = self->strtab + self->symtab[i].st_name;
		const uint32_t  symhash = self->chain[i - self->symoffset];

		if((hash | (uint32_t)1) == (symhash | (uint32_t)1) && 0 == strcmp(symbol, symname)) {
			*symidx = i;
			*symtab = &(self->symtab[i]);
			so_printf("found %s at symidx: %u (GNU_HASH DEF) symtab:%p\n", symbol, *symidx, *symtab);

			return 0;
		}

		//chain ends with an element with the lowest bit set to 1
		if(symhash & (uint32_t)1) {
			break;
		}

		i++;
	}

	so_printf("dont find\n");
	return -1;
}

static int elf_gnu_hash_lookup_undef(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab)
{
	uint32_t i;

	for(i = 0; i < self->symoffset; i++) {
		const char* symname = self->strtab + self->symtab[i].st_name;
		if(0 == strcmp(symname, symbol)) {
			*symidx = i;
			*symtab = &(self->symtab[i]);
			so_printf("found %s at symidx: %u (GNU_HASH UNDEF) symtab:%p\n", symbol, *symidx, *symtab);
			return 0;
		}
	}

	so_printf("dont find\n");
	return -1;
}

static int elf_gnu_hash_lookup(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab)
{
	if(0 == elf_gnu_hash_lookup_def(self, symbol, symidx, symtab)) {
		return 0;
	}
	if(0 == elf_gnu_hash_lookup_undef(self, symbol, symidx, symtab)) {
		return 0;
	}

	so_printf("dont find\n");
	return -1;
}

static int elf_find_symidx_by_name(elf_info_t* self, const char* symbol, uint32_t* symidx, ElfW(Sym)*  *symtab)
{
	if(self->is_use_gnu_hash) {
		return elf_gnu_hash_lookup(self, symbol, symidx, symtab);
	}
	else {
		return elf_hash_lookup(self, symbol, symidx, symtab);
	}
}

static void elf_plain_reloc_iterator_init(elf_plain_reloc_iterator_t* self,
                                          ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela)
{
	self->cur = (uint8_t*)rel;
	self->end = self->cur + rel_sz;
	self->is_use_rela = is_use_rela;

	so_printf("cur:%#x %p rel_sz:%d end:%#x %p is_use_rela:%d\n", self->cur,self->cur,rel_sz,self->end,self->end,is_use_rela);
}

static void* elf_plain_reloc_iterator_next(elf_plain_reloc_iterator_t* self)
{
	if(self->cur >= self->end) {
		so_printf("cur:%#x %p  end:%#x %p\n", self->cur,self->cur,self->end,self->end);
		return NULL;
	}

	void* ret = (void*)(self->cur);
	self->cur += (self->is_use_rela ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));
	so_printf("ret:%#x %p sizeof(ElfW(Rela)):%d sizeof(ElfW(Rel)):%d\n", ret,ret,sizeof(ElfW(Rela)),sizeof(ElfW(Rel)));
	return ret;
}

static int elf_find_and_replace_func(elf_info_t* self, const char* section,
                                     int is_plt, const char* symbol,
                                     void* new_func, void** old_func,
                                     uint32_t symidx, void* rel_common,
                                     int* found)
{
	ElfW(Rela)    *rela;
	ElfW(Rel)     *rel;
	ElfW(Addr)     r_offset;
	size_t         r_info;
	size_t         r_sym;
	size_t         r_type;
	ElfW(Addr)     addr;
	int            r;

	if(NULL != found) {
		*found = 0;
	}

	if(self->is_use_rela) {
		rela = (ElfW(Rela)*)rel_common;
		r_info = rela->r_info;
		r_offset = rela->r_offset;
	}
	else {
		rel = (ElfW(Rel)*)rel_common;
		r_info = rel->r_info;
		r_offset = rel->r_offset;
	}

	//check sym
	r_sym = ELF_R_SYM(r_info);
	if(r_sym != symidx) {
		so_printf("r_sym:%d symidx:%d\n", r_sym,symidx);
		return 0;
	}

	//check type
	r_type = ELF_R_TYPE(r_info);
	if(is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) {
		so_printf("is_plt(%d) && r_type(%d) != ELF_R_GENERIC_JUMP_SLOT(%d)\n", is_plt,r_type,ELF_R_GENERIC_JUMP_SLOT);
		return 0;
	}
	if(!is_plt && (r_type != ELF_R_GENERIC_GLOB_DAT && r_type != ELF_R_GENERIC_ABS)) {
		so_printf("!is_plt(%d) && (r_type(%d) != ELF_R_GENERIC_GLOB_DAT(%d) && r_type != ELF_R_GENERIC_ABS(%d)\n", is_plt,r_type,ELF_R_GENERIC_GLOB_DAT,ELF_R_GENERIC_ABS);
		return 0;
	}

	//we found it
	so_printf("found %s at %s offset: %p %p\n", symbol, section, (void*)r_offset, r_offset);
	if(NULL != found) {
		*found = 1;
	}

	//do replace
	so_printf("self->bias_addr: %p\n", self->bias_addr);
	addr = self->bias_addr + r_offset; /* 指向GOT里需要重定位的地址 */
	so_printf("symbol:%s in GOT addr:%#x %p\n", symbol, addr, addr);
	if(addr < self->base_addr) {
		so_printf("addr(%#x) < self->base_addr(%#x)\n", addr,self->base_addr);
		return -1;
	}
	if(0 != (r = elf_replace_function(self, symbol, addr, new_func, old_func))) {
		so_printf("replace function failed: %s at %s\n", symbol, section);
		return r;
	}

	return 0;
}

static void elf_sleb128_decoder_init(elf_sleb128_decoder_t* self,
                                     ElfW(Addr) rel, ElfW(Word) rel_sz)
{
	self->cur = (uint8_t*)rel;
	self->end = self->cur + rel_sz;
}

static int elf_sleb128_decoder_next(elf_sleb128_decoder_t* self, size_t* ret)
{
	size_t value = 0;
	static const size_t size = 8 * sizeof(value);
	size_t shift = 0;
	uint8_t byte;

	do {
		if(self->cur >= self->end) {
			return -1;
		}

		byte = *(self->cur)++;
		value |= ((size_t)(byte & 127) << shift);
		shift += 7;
	}
	while(byte & 128);

	if(shift < size && (byte & 64)) {
		value |= -((size_t)(1) << shift);
	}

	*ret = value;
	return 0;
}

static int elf_packed_reloc_iterator_init(elf_packed_reloc_iterator_t* self,
                                          ElfW(Addr) rel, ElfW(Word) rel_sz, int is_use_rela)
{
	int r;

	memset(self, 0, sizeof(elf_packed_reloc_iterator_t));
	elf_sleb128_decoder_init(&(self->decoder), rel, rel_sz);
	self->is_use_rela = is_use_rela;

	if(0 != (r = elf_sleb128_decoder_next(&(self->decoder), &(self->relocation_count)))) {
		return r;
	}
	if(0 != (r = elf_sleb128_decoder_next(&(self->decoder), (size_t*)&(self->r_offset)))) {
		return r;
	}
	return 0;
}

static int elf_packed_reloc_iterator_read_group_fields(elf_packed_reloc_iterator_t* self)
{
	int    r;
	size_t val;

	if(0 != (r = elf_sleb128_decoder_next(&(self->decoder), &(self->group_size)))) {
		return r;
	}
	if(0 != (r = elf_sleb128_decoder_next(&(self->decoder), &(self->group_flags)))) {
		return r;
	}

	if(self->group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG)
		if(0 != (r = elf_sleb128_decoder_next(&(self->decoder), &(self->group_r_offset_delta)))) {
			return r;
		}

	if(self->group_flags & RELOCATION_GROUPED_BY_INFO_FLAG)
		if(0 != (r = elf_sleb128_decoder_next(&(self->decoder), (size_t*)&(self->r_info)))) {
			return r;
		}

	if((self->group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) &&
	   (self->group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
		if(0 == self->is_use_rela) {
			so_printf("unexpected r_addend in android.rel section\n");
			return -1;
		}
		if(0 != (r = elf_sleb128_decoder_next(&(self->decoder), &val))) {
			return r;
		}
		self->r_addend += (ssize_t)val;
	}
	else if(0 == (self->group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG)) {
		self->r_addend = 0;
	}

	self->relocation_group_index = 0;
	return 0;
}

static void* elf_packed_reloc_iterator_next(elf_packed_reloc_iterator_t* self)
{
	size_t val;

	if(self->relocation_index >= self->relocation_count) {
		return NULL;
	}

	if(self->relocation_group_index == self->group_size) {
		if(0 != elf_packed_reloc_iterator_read_group_fields(self)) {
			return NULL;
		}
	}

	if(self->group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
		self->r_offset += self->group_r_offset_delta;
	}
	else {
		if(0 != elf_sleb128_decoder_next(&(self->decoder), &val)) {
			return NULL;
		}
		self->r_offset += val;
	}

	if(0 == (self->group_flags & RELOCATION_GROUPED_BY_INFO_FLAG))
		if(0 != elf_sleb128_decoder_next(&(self->decoder), &(self->r_info))) {
			return NULL;
		}

	if(self->is_use_rela &&
	   (self->group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG) &&
	   (0 == (self->group_flags & RELOCATION_GROUPED_BY_ADDEND_FLAG))) {
		if(0 != elf_sleb128_decoder_next(&(self->decoder), &val)) {
			return NULL;
		}
		self->r_addend += (ssize_t)val;
	}

	self->relocation_index++;
	self->relocation_group_index++;

	if(self->is_use_rela) {
		self->rela.r_offset = self->r_offset;
		self->rela.r_info = self->r_info;
		self->rela.r_addend = self->r_addend;
		return (void*)(&(self->rela));
	}
	else {
		self->rel.r_offset = self->r_offset;
		self->rel.r_info = self->r_info;
		return (void*)(&(self->rel));
	}
}

static int elf_replace_function(elf_info_t* self, const char* symbol, ElfW(Addr) addr, void* new_func, void** old_func)
{
	void*         old_addr;
	unsigned int  old_prot = 0;
	unsigned int  need_prot = PROT_READ | PROT_WRITE;
	int           r;

	//already replaced?
	//here we assume that we always have read permission, is this a problem?
	if(*(void**)addr == new_func) {
		so_printf("same, *(void **)addr:%p new_func:%p\n", *(void**)addr,new_func);
		return 0;
	}

	//get old prot
	if(0 != (r = util_get_addr_protect(addr, self->pathname, &old_prot))) {
		so_printf("get addr prot failed. ret: %d\n", r);
		return r;
	}

	if(old_prot != need_prot) {
		//set new prot
		if(0 != (r = util_set_addr_protect(addr, need_prot))) {
			so_printf("set addr prot failed. ret: %d\n", r);
			return r;
		}
	}

	//save old func
	old_addr = *(void**)addr;
	so_printf("symbol:%s old_addr:%p\n", symbol, old_addr);

	if(NULL != old_func) {
		*old_func = old_addr;
	}

	//replace func
	*(void**)addr = new_func;  //segmentation fault sometimes

	if(old_prot != need_prot) {
		//restore the old prot
		if(0 != (r = util_set_addr_protect(addr, old_prot))) {
			so_printf("restore addr prot failed. ret: %d\n", r);
		}
	}

	//clear cache
	util_flush_instruction_cache(addr);

	so_printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>HK_OK GOT addr %p: %p -> %p %s %s\n", (void*)addr, old_addr, new_func, symbol, self->pathname);
	return 0;
}

void* hk_show_sym_info(int pid, const char* sym_name, const char* so_name)
{
	so_printf("sym_name:%s so_name:%s\n", sym_name, so_name);

	uintptr_t base_addr = get_elf_addr(pid, so_name);
	so_printf("base_addr:%p\n", base_addr);

	if(0 != check_elfheader(base_addr)) {
		so_printf("check_elfheader error\n");
		return;
	}

	if(0 != elf_init(&elf_info, base_addr, so_name)) {
		so_printf("error: elf_init fail\n");
		return;
	}

	so_printf("\nnow we have pased all elfinfo, try to find syminfo from gnu or sys hash\n");

	int r;
	uint32_t symidx;
	ElfW(Sym)*  symtab;

	if(0 != (r = elf_find_symidx_by_name(&elf_info, sym_name, &symidx, &(symtab)))) {
		return;
	}
	so_printf("find symbol:%s symidx:%d dynsym.st_value = %p, dynsym.size = %p\n",
	            sym_name, symidx, (symtab)->st_value, (symtab)->st_size);
//        so_printf("old_func:%p new_func:%p\n", *(hook_info[i].old_func),(hook_info[i].new_func));
	void* ret = (elf_info.bias_addr+(symtab)->st_value);
	so_printf("bias_addr(%p)+(symtab)->st_value(%p):[ %p ] [%s] in [%s]\n",
	            elf_info.bias_addr,(symtab)->st_value,ret,sym_name, so_name);

	return ret;
}

/* get all elf info */
void* hk_get_elfinfo(const char* elf_name)
{
	uintptr_t base_addr = get_elf_addr(-1, elf_name);
	so_printf("%s base_addr:%p\n", elf_name, base_addr);

	if(0 != check_elfheader(base_addr)) {
		so_printf("check_elfheader error\n");
		return 0;
	}

	if(0 != elf_init(&elf_info, base_addr, elf_name)) {
		so_printf("error: elf_init fail\n");
		return 0;
	}

	so_printf("\nnow we have parsed %s all elfinfo\n", elf_name);
	return &elf_info;
}

/* hook func */
int hk_hook(void* elf, const char* sym, FUNC_PROXY proxy)
{
	uint32_t                        symidx;
	void*                           rel_common;
	elf_plain_reloc_iterator_t   plain_iter;
	elf_packed_reloc_iterator_t  packed_iter;
	int                             found;
	int                             r;
	ElfW(Addr)     addr;

	elf_info_t* self = (elf_info_t*)elf;

	if(NULL == self->pathname) {
		so_printf("error, not inited\n");
		return -1; //not inited?
	}

	if(NULL == sym || NULL == proxy) {
		return -1;
	}

	ElfW(Sym)*  symtab;
	if(0 != (r = elf_find_symidx_by_name(self, sym, &symidx, &symtab))) {
		return 0;
	}
    so_printf("find symbol:%s symidx:%d dynsym.st_value = %p, dynsym.size = %p\n",
                sym, symidx, (symtab)->st_value, (symtab)->st_size);
    void* ret_addr = (self->bias_addr+(symtab)->st_value);
    so_printf("bias_addr(%p)+(symtab)->st_value(%p):[ %p ] [%s] in [%s]\n",
                self->bias_addr,(symtab)->st_value,ret_addr,sym, self->pathname);

    void *old_func = NULL;
	//replace for .rel(a).plt
	if(0 != self->relplt) {
		elf_plain_reloc_iterator_init(&plain_iter, self->relplt, self->relplt_sz, self->is_use_rela);
		so_printf("self->relplt:%p self->relplt_sz:%d\n", self->relplt,self->relplt_sz);
		/* 遍历.rel(a).plt */
		while(NULL != (rel_common = elf_plain_reloc_iterator_next(&plain_iter))) {
			if(0 != (r = elf_find_and_replace_func(self,
			                                       (self->is_use_rela ? ".rela.plt" : ".rel.plt"), 1,
			                                       sym, proxy, &old_func,
			                                       symidx, rel_common, &found))) {
				return r;
			}
			if(found) {
				break;
			}
		}
	}

	//replace for .rel(a).dyn
	if(0 != self->reldyn) {
		so_printf("self->reldyn != 0\n");

		elf_plain_reloc_iterator_init(&plain_iter, self->reldyn, self->reldyn_sz, self->is_use_rela);
		while(NULL != (rel_common = elf_plain_reloc_iterator_next(&plain_iter))) {
			if(0 != (r = elf_find_and_replace_func(self,
			                                       (self->is_use_rela ? ".rela.dyn" : ".rel.dyn"), 0,
			                                       sym, proxy, &old_func,
			                                       symidx, rel_common, NULL))) {
				return r;
			}
		}
	}

	//replace for .rel(a).android
	if(0 != self->relandroid) {
		so_printf("self->relandroid != 0\n");

		elf_packed_reloc_iterator_init(&packed_iter, self->relandroid, self->relandroid_sz, self->is_use_rela);
		while(NULL != (rel_common = elf_packed_reloc_iterator_next(&packed_iter))) {
			if(0 != (r = elf_find_and_replace_func(self,
			                                       (self->is_use_rela ? ".rela.android" : ".rel.android"), 0,
			                                       sym, proxy, &old_func,
			                                       symidx, rel_common, NULL))) {
				return r;
			}
		}
	}

    return 0;
}


/*>Begin>> */
typedef struct _hook_info {
	const char* symbol; /* need hook func */
	FUNC_PROXY proxy; /* proxy func */
} hook_info_t;

void lib_init(void) __attribute__((constructor));

const char* libc_path = "/lib/i386-linux-gnu/libc-2.23.so";
const char* linker_path = "/lib/i386-linux-gnu/libdl-2.23.so";
const char* libc_name = "libc-2.23.so";
const char* libdl_name = "libdl-2.23.so";
const char* hooked_elf = "host";

//const char *libc_path = "/usr/libx32/libc.so.6";
//const char *linker_path = "/usr/libx32/ld-linux-x32.so.2";
//const char *libc_name = "libc.so.6";

static void* hook_malloc(size_t size);
static void hook_free(void* p);


static hook_info_t hook_list[] = {
	{
		.symbol = __MS(malloc),
		.proxy = hook_malloc
	},
	{
		.symbol = __MS(free),
		.proxy = hook_free
	},
};

void lib_init(void)
{
	so_printf("\n\n\nCan u see me? i am in constructor init, i will appear after dlopen\n\n");

    so_printf("\ntry to hook\n");
    
	void* elf = hk_get_elfinfo(hooked_elf);
	if(elf) {
		for(int i = 0; i < ARRAY_SIZE(hook_list); i++) {
			hk_hook(elf, hook_list[i].symbol, hook_list[i].proxy);
		}
	}

	so_printf("\n\n\nlib_init exit!\n\n\n");
}

static void* hook_malloc(size_t size)
{
    so_printf("hook_malloc\n");
	void* ret = malloc(size); /* use it via this so's plt->got */
	if(ret) {
		so_printf("malloc %d at %p\n", size, ret);
	}

	return ret;
}

static void hook_free(void* p)
{
    so_printf("hook_free\n");
	free(p); /* use it via this so's plt->got */
	so_printf("free at %p\n", p);
}

int hook_entry(char* a)
{
	so_printf("Hook success, pid = %d\n", getpid());
	so_printf("Hello %s\n", a);
    
	return 0;
}


