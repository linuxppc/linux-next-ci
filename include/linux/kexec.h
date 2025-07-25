/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_KEXEC_H
#define LINUX_KEXEC_H

#define IND_DESTINATION_BIT 0
#define IND_INDIRECTION_BIT 1
#define IND_DONE_BIT        2
#define IND_SOURCE_BIT      3

#define IND_DESTINATION  (1 << IND_DESTINATION_BIT)
#define IND_INDIRECTION  (1 << IND_INDIRECTION_BIT)
#define IND_DONE         (1 << IND_DONE_BIT)
#define IND_SOURCE       (1 << IND_SOURCE_BIT)
#define IND_FLAGS (IND_DESTINATION | IND_INDIRECTION | IND_DONE | IND_SOURCE)

#if !defined(__ASSEMBLY__)

#include <linux/vmcore_info.h>
#include <linux/crash_reserve.h>
#include <asm/io.h>
#include <linux/range.h>

#include <uapi/linux/kexec.h>
#include <linux/verification.h>

extern note_buf_t __percpu *crash_notes;

#ifdef CONFIG_CRASH_DUMP
#include <linux/prandom.h>
#endif

#ifdef CONFIG_KEXEC_CORE
#include <linux/list.h>
#include <linux/compat.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <asm/kexec.h>
#include <linux/crash_core.h>

/* Verify architecture specific macros are defined */

#ifndef KEXEC_SOURCE_MEMORY_LIMIT
#error KEXEC_SOURCE_MEMORY_LIMIT not defined
#endif

#ifndef KEXEC_DESTINATION_MEMORY_LIMIT
#error KEXEC_DESTINATION_MEMORY_LIMIT not defined
#endif

#ifndef KEXEC_CONTROL_MEMORY_LIMIT
#error KEXEC_CONTROL_MEMORY_LIMIT not defined
#endif

#ifndef KEXEC_CONTROL_MEMORY_GFP
#define KEXEC_CONTROL_MEMORY_GFP (GFP_KERNEL | __GFP_NORETRY)
#endif

#ifndef KEXEC_CONTROL_PAGE_SIZE
#error KEXEC_CONTROL_PAGE_SIZE not defined
#endif

#ifndef KEXEC_ARCH
#error KEXEC_ARCH not defined
#endif

#ifndef KEXEC_CRASH_CONTROL_MEMORY_LIMIT
#define KEXEC_CRASH_CONTROL_MEMORY_LIMIT KEXEC_CONTROL_MEMORY_LIMIT
#endif

#ifndef KEXEC_CRASH_MEM_ALIGN
#define KEXEC_CRASH_MEM_ALIGN PAGE_SIZE
#endif

/*
 * This structure is used to hold the arguments that are used when loading
 * kernel binaries.
 */

typedef unsigned long kimage_entry_t;

/*
 * This is a copy of the UAPI struct kexec_segment and must be identical
 * to it because it gets copied straight from user space into kernel
 * memory. Do not modify this structure unless you change the way segments
 * get ingested from user space.
 */
struct kexec_segment {
	/*
	 * This pointer can point to user memory if kexec_load() system
	 * call is used or will point to kernel memory if
	 * kexec_file_load() system call is used.
	 *
	 * Use ->buf when expecting to deal with user memory and use ->kbuf
	 * when expecting to deal with kernel memory.
	 */
	union {
		void __user *buf;
		void *kbuf;
	};
	size_t bufsz;
	unsigned long mem;
	size_t memsz;
};

#ifdef CONFIG_COMPAT
struct compat_kexec_segment {
	compat_uptr_t buf;
	compat_size_t bufsz;
	compat_ulong_t mem;	/* User space sees this as a (void *) ... */
	compat_size_t memsz;
};
#endif

#ifdef CONFIG_KEXEC_FILE
struct purgatory_info {
	/*
	 * Pointer to elf header at the beginning of kexec_purgatory.
	 * Note: kexec_purgatory is read only
	 */
	const Elf_Ehdr *ehdr;
	/*
	 * Temporary, modifiable buffer for sechdrs used for relocation.
	 * This memory can be freed post image load.
	 */
	Elf_Shdr *sechdrs;
	/*
	 * Temporary, modifiable buffer for stripped purgatory used for
	 * relocation. This memory can be freed post image load.
	 */
	void *purgatory_buf;
};

struct kimage;

typedef int (kexec_probe_t)(const char *kernel_buf, unsigned long kernel_size);
typedef void *(kexec_load_t)(struct kimage *image, char *kernel_buf,
			     unsigned long kernel_len, char *initrd,
			     unsigned long initrd_len, char *cmdline,
			     unsigned long cmdline_len);
typedef int (kexec_cleanup_t)(void *loader_data);

#ifdef CONFIG_KEXEC_SIG
typedef int (kexec_verify_sig_t)(const char *kernel_buf,
				 unsigned long kernel_len);
#endif

struct kexec_file_ops {
	kexec_probe_t *probe;
	kexec_load_t *load;
	kexec_cleanup_t *cleanup;
#ifdef CONFIG_KEXEC_SIG
	kexec_verify_sig_t *verify_sig;
#endif
};

extern const struct kexec_file_ops * const kexec_file_loaders[];

int kexec_image_probe_default(struct kimage *image, void *buf,
			      unsigned long buf_len);
int kexec_image_post_load_cleanup_default(struct kimage *image);

/*
 * If kexec_buf.mem is set to this value, kexec_locate_mem_hole()
 * will try to allocate free memory. Arch may overwrite it.
 */
#ifndef KEXEC_BUF_MEM_UNKNOWN
#define KEXEC_BUF_MEM_UNKNOWN 0
#endif

/**
 * struct kexec_buf - parameters for finding a place for a buffer in memory
 * @image:	kexec image in which memory to search.
 * @buffer:	Contents which will be copied to the allocated memory.
 * @bufsz:	Size of @buffer.
 * @mem:	On return will have address of the buffer in memory.
 * @memsz:	Size for the buffer in memory.
 * @buf_align:	Minimum alignment needed.
 * @buf_min:	The buffer can't be placed below this address.
 * @buf_max:	The buffer can't be placed above this address.
 * @cma:	CMA page if the buffer is backed by CMA.
 * @top_down:	Allocate from top of memory.
 * @random:	Place the buffer at a random position.
 */
struct kexec_buf {
	struct kimage *image;
	void *buffer;
	unsigned long bufsz;
	unsigned long mem;
	unsigned long memsz;
	unsigned long buf_align;
	unsigned long buf_min;
	unsigned long buf_max;
	struct page *cma;
	bool top_down;
#ifdef CONFIG_CRASH_DUMP
	bool random;
#endif
};


#ifdef CONFIG_CRASH_DUMP
static inline void kexec_random_range_start(unsigned long start,
					    unsigned long end,
					    struct kexec_buf *kbuf,
					    unsigned long *temp_start)
{
	unsigned short i;

	if (kbuf->random) {
		get_random_bytes(&i, sizeof(unsigned short));
		*temp_start = start + (end - start) / USHRT_MAX * i;
	}
}
#else
static inline void kexec_random_range_start(unsigned long start,
					    unsigned long end,
					    struct kexec_buf *kbuf,
					    unsigned long *temp_start)
{}
#endif

int kexec_load_purgatory(struct kimage *image, struct kexec_buf *kbuf);
int kexec_purgatory_get_set_symbol(struct kimage *image, const char *name,
				   void *buf, unsigned int size,
				   bool get_value);
void *kexec_purgatory_get_symbol_addr(struct kimage *image, const char *name);

#ifndef arch_kexec_kernel_image_probe
static inline int
arch_kexec_kernel_image_probe(struct kimage *image, void *buf, unsigned long buf_len)
{
	return kexec_image_probe_default(image, buf, buf_len);
}
#endif

#ifndef arch_kimage_file_post_load_cleanup
static inline int arch_kimage_file_post_load_cleanup(struct kimage *image)
{
	return kexec_image_post_load_cleanup_default(image);
}
#endif

#ifndef arch_check_excluded_range
static inline int arch_check_excluded_range(struct kimage *image,
					    unsigned long start,
					    unsigned long end)
{
	return 0;
}
#endif

#ifdef CONFIG_KEXEC_SIG
#ifdef CONFIG_SIGNED_PE_FILE_VERIFICATION
int kexec_kernel_verify_pe_sig(const char *kernel, unsigned long kernel_len);
#endif
#endif

extern int kexec_add_buffer(struct kexec_buf *kbuf);
int kexec_locate_mem_hole(struct kexec_buf *kbuf);

#ifndef arch_kexec_locate_mem_hole
/**
 * arch_kexec_locate_mem_hole - Find free memory to place the segments.
 * @kbuf:                       Parameters for the memory search.
 *
 * On success, kbuf->mem will have the start address of the memory region found.
 *
 * Return: 0 on success, negative errno on error.
 */
static inline int arch_kexec_locate_mem_hole(struct kexec_buf *kbuf)
{
	return kexec_locate_mem_hole(kbuf);
}
#endif

#ifndef arch_kexec_apply_relocations_add
/*
 * arch_kexec_apply_relocations_add - apply relocations of type RELA
 * @pi:		Purgatory to be relocated.
 * @section:	Section relocations applying to.
 * @relsec:	Section containing RELAs.
 * @symtab:	Corresponding symtab.
 *
 * Return: 0 on success, negative errno on error.
 */
static inline int
arch_kexec_apply_relocations_add(struct purgatory_info *pi, Elf_Shdr *section,
				 const Elf_Shdr *relsec, const Elf_Shdr *symtab)
{
	pr_err("RELA relocation unsupported.\n");
	return -ENOEXEC;
}
#endif

#ifndef arch_kexec_apply_relocations
/*
 * arch_kexec_apply_relocations - apply relocations of type REL
 * @pi:		Purgatory to be relocated.
 * @section:	Section relocations applying to.
 * @relsec:	Section containing RELs.
 * @symtab:	Corresponding symtab.
 *
 * Return: 0 on success, negative errno on error.
 */
static inline int
arch_kexec_apply_relocations(struct purgatory_info *pi, Elf_Shdr *section,
			     const Elf_Shdr *relsec, const Elf_Shdr *symtab)
{
	pr_err("REL relocation unsupported.\n");
	return -ENOEXEC;
}
#endif
#endif /* CONFIG_KEXEC_FILE */

#ifdef CONFIG_KEXEC_ELF
struct kexec_elf_info {
	/*
	 * Where the ELF binary contents are kept.
	 * Memory managed by the user of the struct.
	 */
	const char *buffer;

	const struct elfhdr *ehdr;
	const struct elf_phdr *proghdrs;
};

int kexec_build_elf_info(const char *buf, size_t len, struct elfhdr *ehdr,
			       struct kexec_elf_info *elf_info);

int kexec_elf_load(struct kimage *image, struct elfhdr *ehdr,
			 struct kexec_elf_info *elf_info,
			 struct kexec_buf *kbuf,
			 unsigned long *lowest_load_addr);

void kexec_free_elf_info(struct kexec_elf_info *elf_info);
int kexec_elf_probe(const char *buf, unsigned long len);
#endif
struct kimage {
	kimage_entry_t head;
	kimage_entry_t *entry;
	kimage_entry_t *last_entry;

	unsigned long start;
	struct page *control_code_page;
	struct page *swap_page;
	void *vmcoreinfo_data_copy; /* locates in the crash memory */

	unsigned long nr_segments;
	struct kexec_segment segment[KEXEC_SEGMENT_MAX];
	struct page *segment_cma[KEXEC_SEGMENT_MAX];

	struct list_head control_pages;
	struct list_head dest_pages;
	struct list_head unusable_pages;

	/* Address of next control page to allocate for crash kernels. */
	unsigned long control_page;

	/* Flags to indicate special processing */
	unsigned int type : 1;
#define KEXEC_TYPE_DEFAULT 0
#define KEXEC_TYPE_CRASH   1
	unsigned int preserve_context : 1;
	/* If set, we are using file mode kexec syscall */
	unsigned int file_mode:1;
#ifdef CONFIG_CRASH_HOTPLUG
	/* If set, it is safe to update kexec segments that are
	 * excluded from SHA calculation.
	 */
	unsigned int hotplug_support:1;
#endif
	unsigned int no_cma:1;

#ifdef ARCH_HAS_KIMAGE_ARCH
	struct kimage_arch arch;
#endif

#ifdef CONFIG_KEXEC_FILE
	/* Additional fields for file based kexec syscall */
	void *kernel_buf;
	unsigned long kernel_buf_len;

	void *initrd_buf;
	unsigned long initrd_buf_len;

	char *cmdline_buf;
	unsigned long cmdline_buf_len;

	/* File operations provided by image loader */
	const struct kexec_file_ops *fops;

	/* Image loader handling the kernel can store a pointer here */
	void *image_loader_data;

	/* Information for loading purgatory */
	struct purgatory_info purgatory_info;
#endif

#ifdef CONFIG_CRASH_HOTPLUG
	int hp_action;
	int elfcorehdr_index;
	bool elfcorehdr_updated;
#endif

#ifdef CONFIG_IMA_KEXEC
	/* Virtual address of IMA measurement buffer for kexec syscall */
	void *ima_buffer;

	phys_addr_t ima_buffer_addr;
	size_t ima_buffer_size;

	unsigned long ima_segment_index;
	bool is_ima_segment_index_set;
#endif

	struct {
		struct kexec_segment *scratch;
		phys_addr_t fdt;
	} kho;

	/* Core ELF header buffer */
	void *elf_headers;
	unsigned long elf_headers_sz;
	unsigned long elf_load_addr;

	/* dm crypt keys buffer */
	unsigned long dm_crypt_keys_addr;
	unsigned long dm_crypt_keys_sz;
};

/* kexec interface functions */
extern void machine_kexec(struct kimage *image);
extern int machine_kexec_prepare(struct kimage *image);
extern void machine_kexec_cleanup(struct kimage *image);
extern int kernel_kexec(void);
extern struct page *kimage_alloc_control_pages(struct kimage *image,
						unsigned int order);

#ifndef machine_kexec_post_load
static inline int machine_kexec_post_load(struct kimage *image) { return 0; }
#endif

extern struct kimage *kexec_image;
extern struct kimage *kexec_crash_image;

bool kexec_load_permitted(int kexec_image_type);

#ifndef kexec_flush_icache_page
#define kexec_flush_icache_page(page)
#endif

/* List of defined/legal kexec flags */
#ifndef CONFIG_KEXEC_JUMP
#define KEXEC_FLAGS    (KEXEC_ON_CRASH | KEXEC_UPDATE_ELFCOREHDR | KEXEC_CRASH_HOTPLUG_SUPPORT)
#else
#define KEXEC_FLAGS    (KEXEC_ON_CRASH | KEXEC_PRESERVE_CONTEXT | KEXEC_UPDATE_ELFCOREHDR | \
			KEXEC_CRASH_HOTPLUG_SUPPORT)
#endif

/* List of defined/legal kexec file flags */
#define KEXEC_FILE_FLAGS	(KEXEC_FILE_UNLOAD | KEXEC_FILE_ON_CRASH | \
				 KEXEC_FILE_NO_INITRAMFS | KEXEC_FILE_DEBUG)

/* flag to track if kexec reboot is in progress */
extern bool kexec_in_progress;

#ifndef page_to_boot_pfn
static inline unsigned long page_to_boot_pfn(struct page *page)
{
	return page_to_pfn(page);
}
#endif

#ifndef boot_pfn_to_page
static inline struct page *boot_pfn_to_page(unsigned long boot_pfn)
{
	return pfn_to_page(boot_pfn);
}
#endif

#ifndef phys_to_boot_phys
static inline unsigned long phys_to_boot_phys(phys_addr_t phys)
{
	return phys;
}
#endif

#ifndef boot_phys_to_phys
static inline phys_addr_t boot_phys_to_phys(unsigned long boot_phys)
{
	return boot_phys;
}
#endif

#ifndef crash_free_reserved_phys_range
static inline void crash_free_reserved_phys_range(unsigned long begin, unsigned long end)
{
	unsigned long addr;

	for (addr = begin; addr < end; addr += PAGE_SIZE)
		free_reserved_page(boot_pfn_to_page(addr >> PAGE_SHIFT));
}
#endif

static inline unsigned long virt_to_boot_phys(void *addr)
{
	return phys_to_boot_phys(__pa((unsigned long)addr));
}

static inline void *boot_phys_to_virt(unsigned long entry)
{
	return phys_to_virt(boot_phys_to_phys(entry));
}

#ifndef arch_kexec_post_alloc_pages
static inline int arch_kexec_post_alloc_pages(void *vaddr, unsigned int pages, gfp_t gfp) { return 0; }
#endif

#ifndef arch_kexec_pre_free_pages
static inline void arch_kexec_pre_free_pages(void *vaddr, unsigned int pages) { }
#endif

extern bool kexec_file_dbg_print;

#define kexec_dprintk(fmt, arg...) \
        do { if (kexec_file_dbg_print) pr_info(fmt, ##arg); } while (0)

extern void *kimage_map_segment(struct kimage *image, unsigned long addr, unsigned long size);
extern void kimage_unmap_segment(void *buffer);
#else /* !CONFIG_KEXEC_CORE */
struct pt_regs;
struct task_struct;
struct kimage;
static inline void __crash_kexec(struct pt_regs *regs) { }
static inline void crash_kexec(struct pt_regs *regs) { }
static inline int kexec_should_crash(struct task_struct *p) { return 0; }
static inline int kexec_crash_loaded(void) { return 0; }
static inline void *kimage_map_segment(struct kimage *image, unsigned long addr, unsigned long size)
{ return NULL; }
static inline void kimage_unmap_segment(void *buffer) { }
#define kexec_in_progress false
#endif /* CONFIG_KEXEC_CORE */

#ifdef CONFIG_KEXEC_SIG
void set_kexec_sig_enforced(void);
#else
static inline void set_kexec_sig_enforced(void) {}
#endif

#endif /* !defined(__ASSEBMLY__) */

#endif /* LINUX_KEXEC_H */
