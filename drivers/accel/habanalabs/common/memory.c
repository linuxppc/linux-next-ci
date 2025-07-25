// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2016-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <uapi/drm/habanalabs_accel.h>
#include "habanalabs.h"
#include "../include/hw_ip/mmu/mmu_general.h"

#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pci-p2pdma.h>

MODULE_IMPORT_NS("DMA_BUF");

#define HL_MMU_DEBUG	0

/* use small pages for supporting non-pow2 (32M/40M/48M) DRAM phys page sizes */
#define DRAM_POOL_PAGE_SIZE	SZ_8M

#define MEM_HANDLE_INVALID	ULONG_MAX

static int allocate_timestamps_buffers(struct hl_fpriv *hpriv,
			struct hl_mem_in *args, u64 *handle);

static int set_alloc_page_size(struct hl_device *hdev, struct hl_mem_in *args, u32 *page_size)
{
	struct asic_fixed_properties *prop = &hdev->asic_prop;
	u64 psize;

	/*
	 * for ASIC that supports setting the allocation page size by user we will address
	 * user's choice only if it is not 0 (as 0 means taking the default page size)
	 */
	if (prop->supports_user_set_page_size && args->alloc.page_size) {
		psize = args->alloc.page_size;

		if (!is_power_of_2(psize)) {
			dev_err(hdev->dev, "user page size (%#llx) is not power of 2\n", psize);
			return -EINVAL;
		}
	} else {
		psize = prop->device_mem_alloc_default_page_size;
	}

	*page_size = psize;

	return 0;
}

/*
 * The va ranges in context object contain a list with the available chunks of
 * device virtual memory.
 * There is one range for host allocations and one for DRAM allocations.
 *
 * On initialization each range contains one chunk of all of its available
 * virtual range which is a half of the total device virtual range.
 *
 * On each mapping of physical pages, a suitable virtual range chunk (with a
 * minimum size) is selected from the list. If the chunk size equals the
 * requested size, the chunk is returned. Otherwise, the chunk is split into
 * two chunks - one to return as result and a remainder to stay in the list.
 *
 * On each Unmapping of a virtual address, the relevant virtual chunk is
 * returned to the list. The chunk is added to the list and if its edges match
 * the edges of the adjacent chunks (means a contiguous chunk can be created),
 * the chunks are merged.
 *
 * On finish, the list is checked to have only one chunk of all the relevant
 * virtual range (which is a half of the device total virtual range).
 * If not (means not all mappings were unmapped), a warning is printed.
 */

/*
 * alloc_device_memory() - allocate device memory.
 * @ctx: pointer to the context structure.
 * @args: host parameters containing the requested size.
 * @ret_handle: result handle.
 *
 * This function does the following:
 * - Allocate the requested size rounded up to 'dram_page_size' pages.
 * - Return unique handle for later map/unmap/free.
 */
static int alloc_device_memory(struct hl_ctx *ctx, struct hl_mem_in *args,
				u32 *ret_handle)
{
	struct hl_device *hdev = ctx->hdev;
	struct hl_vm *vm = &hdev->vm;
	struct hl_vm_phys_pg_pack *phys_pg_pack;
	u64 paddr = 0, total_size, num_pgs, i;
	u32 num_curr_pgs, page_size;
	bool contiguous;
	int handle, rc;

	num_curr_pgs = 0;

	rc = set_alloc_page_size(hdev, args, &page_size);
	if (rc)
		return rc;

	num_pgs = DIV_ROUND_UP_ULL(args->alloc.mem_size, page_size);
	total_size = num_pgs * page_size;

	if (!total_size) {
		dev_err(hdev->dev, "Cannot allocate 0 bytes\n");
		return -EINVAL;
	}

	contiguous = args->flags & HL_MEM_CONTIGUOUS;

	if (contiguous) {
		if (is_power_of_2(page_size))
			paddr = (uintptr_t) gen_pool_dma_alloc_align(vm->dram_pg_pool,
								     total_size, NULL, page_size);
		else
			paddr = gen_pool_alloc(vm->dram_pg_pool, total_size);
		if (!paddr) {
			dev_err(hdev->dev,
				"Cannot allocate %llu contiguous pages with total size of %llu\n",
				num_pgs, total_size);
			return -ENOMEM;
		}
	}

	phys_pg_pack = kzalloc(sizeof(*phys_pg_pack), GFP_KERNEL);
	if (!phys_pg_pack) {
		rc = -ENOMEM;
		goto pages_pack_err;
	}

	phys_pg_pack->vm_type = VM_TYPE_PHYS_PACK;
	phys_pg_pack->asid = ctx->asid;
	phys_pg_pack->npages = num_pgs;
	phys_pg_pack->page_size = page_size;
	phys_pg_pack->total_size = total_size;
	phys_pg_pack->flags = args->flags;
	phys_pg_pack->contiguous = contiguous;

	phys_pg_pack->pages = kvmalloc_array(num_pgs, sizeof(u64), GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(phys_pg_pack->pages)) {
		rc = -ENOMEM;
		goto pages_arr_err;
	}

	if (phys_pg_pack->contiguous) {
		for (i = 0 ; i < num_pgs ; i++)
			phys_pg_pack->pages[i] = paddr + i * page_size;
	} else {
		for (i = 0 ; i < num_pgs ; i++) {
			if (is_power_of_2(page_size))
				phys_pg_pack->pages[i] =
					(uintptr_t)gen_pool_dma_alloc_align(vm->dram_pg_pool,
									    page_size, NULL,
									    page_size);
			else
				phys_pg_pack->pages[i] = gen_pool_alloc(vm->dram_pg_pool,
									page_size);

			if (!phys_pg_pack->pages[i]) {
				dev_err(hdev->dev,
					"Cannot allocate device memory (out of memory)\n");
				rc = -ENOMEM;
				goto page_err;
			}

			num_curr_pgs++;
		}
	}

	spin_lock(&vm->idr_lock);
	handle = idr_alloc(&vm->phys_pg_pack_handles, phys_pg_pack, 1, 0,
				GFP_ATOMIC);
	spin_unlock(&vm->idr_lock);

	if (handle < 0) {
		dev_err(hdev->dev, "Failed to get handle for page\n");
		rc = -EFAULT;
		goto idr_err;
	}

	for (i = 0 ; i < num_pgs ; i++)
		kref_get(&vm->dram_pg_pool_refcount);

	phys_pg_pack->handle = handle;

	atomic64_add(phys_pg_pack->total_size, &ctx->dram_phys_mem);
	atomic64_add(phys_pg_pack->total_size, &hdev->dram_used_mem);

	*ret_handle = handle;

	return 0;

idr_err:
page_err:
	if (!phys_pg_pack->contiguous)
		for (i = 0 ; i < num_curr_pgs ; i++)
			gen_pool_free(vm->dram_pg_pool, phys_pg_pack->pages[i],
					page_size);

	kvfree(phys_pg_pack->pages);
pages_arr_err:
	kfree(phys_pg_pack);
pages_pack_err:
	if (contiguous)
		gen_pool_free(vm->dram_pg_pool, paddr, total_size);

	return rc;
}

/**
 * dma_map_host_va() - DMA mapping of the given host virtual address.
 * @hdev: habanalabs device structure.
 * @addr: the host virtual address of the memory area.
 * @size: the size of the memory area.
 * @p_userptr: pointer to result userptr structure.
 *
 * This function does the following:
 * - Allocate userptr structure.
 * - Pin the given host memory using the userptr structure.
 * - Perform DMA mapping to have the DMA addresses of the pages.
 */
static int dma_map_host_va(struct hl_device *hdev, u64 addr, u64 size,
				struct hl_userptr **p_userptr)
{
	struct hl_userptr *userptr;
	int rc;

	userptr = kzalloc(sizeof(*userptr), GFP_KERNEL);
	if (!userptr) {
		rc = -ENOMEM;
		goto userptr_err;
	}

	rc = hl_pin_host_memory(hdev, addr, size, userptr);
	if (rc)
		goto pin_err;

	userptr->dma_mapped = true;
	userptr->dir = DMA_BIDIRECTIONAL;
	userptr->vm_type = VM_TYPE_USERPTR;

	*p_userptr = userptr;

	rc = hl_dma_map_sgtable(hdev, userptr->sgt, DMA_BIDIRECTIONAL);
	if (rc) {
		dev_err(hdev->dev, "failed to map sgt with DMA region\n");
		goto dma_map_err;
	}

	return 0;

dma_map_err:
	hl_unpin_host_memory(hdev, userptr);
pin_err:
	kfree(userptr);
userptr_err:

	return rc;
}

/**
 * dma_unmap_host_va() - DMA unmapping of the given host virtual address.
 * @hdev: habanalabs device structure.
 * @userptr: userptr to free.
 *
 * This function does the following:
 * - Unpins the physical pages.
 * - Frees the userptr structure.
 */
static void dma_unmap_host_va(struct hl_device *hdev,
				struct hl_userptr *userptr)
{
	hl_unpin_host_memory(hdev, userptr);
	kfree(userptr);
}

/**
 * dram_pg_pool_do_release() - free DRAM pages pool
 * @ref: pointer to reference object.
 *
 * This function does the following:
 * - Frees the idr structure of physical pages handles.
 * - Frees the generic pool of DRAM physical pages.
 */
static void dram_pg_pool_do_release(struct kref *ref)
{
	struct hl_vm *vm = container_of(ref, struct hl_vm,
			dram_pg_pool_refcount);

	/*
	 * free the idr here as only here we know for sure that there are no
	 * allocated physical pages and hence there are no handles in use
	 */
	idr_destroy(&vm->phys_pg_pack_handles);
	gen_pool_destroy(vm->dram_pg_pool);
}

/**
 * free_phys_pg_pack() - free physical page pack.
 * @hdev: habanalabs device structure.
 * @phys_pg_pack: physical page pack to free.
 *
 * This function does the following:
 * - For DRAM memory only
 *   - iterate over the pack, free each physical block structure by
 *     returning it to the general pool.
 * - Free the hl_vm_phys_pg_pack structure.
 */
static void free_phys_pg_pack(struct hl_device *hdev,
				struct hl_vm_phys_pg_pack *phys_pg_pack)
{
	struct hl_vm *vm = &hdev->vm;
	u64 i;

	if (phys_pg_pack->created_from_userptr)
		goto end;

	if (phys_pg_pack->contiguous) {
		gen_pool_free(vm->dram_pg_pool, phys_pg_pack->pages[0],
			phys_pg_pack->total_size);

		for (i = 0; i < phys_pg_pack->npages ; i++)
			kref_put(&vm->dram_pg_pool_refcount,
				dram_pg_pool_do_release);
	} else {
		for (i = 0 ; i < phys_pg_pack->npages ; i++) {
			gen_pool_free(vm->dram_pg_pool,
				phys_pg_pack->pages[i],
				phys_pg_pack->page_size);
			kref_put(&vm->dram_pg_pool_refcount,
				dram_pg_pool_do_release);
		}
	}

end:
	kvfree(phys_pg_pack->pages);
	kfree(phys_pg_pack);

	return;
}

/**
 * free_device_memory() - free device memory.
 * @ctx: pointer to the context structure.
 * @args: host parameters containing the requested size.
 *
 * This function does the following:
 * - Free the device memory related to the given handle.
 */
static int free_device_memory(struct hl_ctx *ctx, struct hl_mem_in *args)
{
	struct hl_device *hdev = ctx->hdev;
	struct hl_vm *vm = &hdev->vm;
	struct hl_vm_phys_pg_pack *phys_pg_pack;
	u32 handle = args->free.handle;

	spin_lock(&vm->idr_lock);
	phys_pg_pack = idr_find(&vm->phys_pg_pack_handles, handle);
	if (!phys_pg_pack) {
		spin_unlock(&vm->idr_lock);
		dev_err(hdev->dev, "free device memory failed, no match for handle %u\n", handle);
		return -EINVAL;
	}

	if (atomic_read(&phys_pg_pack->mapping_cnt) > 0) {
		spin_unlock(&vm->idr_lock);
		dev_err(hdev->dev, "handle %u is mapped, cannot free\n", handle);
		return -EINVAL;
	}

	/* must remove from idr before the freeing of the physical pages as the refcount of the pool
	 * is also the trigger of the idr destroy
	 */
	idr_remove(&vm->phys_pg_pack_handles, handle);
	spin_unlock(&vm->idr_lock);

	atomic64_sub(phys_pg_pack->total_size, &ctx->dram_phys_mem);
	atomic64_sub(phys_pg_pack->total_size, &hdev->dram_used_mem);

	free_phys_pg_pack(hdev, phys_pg_pack);

	return 0;
}

/**
 * clear_va_list_locked() - free virtual addresses list.
 * @hdev: habanalabs device structure.
 * @va_list: list of virtual addresses to free.
 *
 * This function does the following:
 * - Iterate over the list and free each virtual addresses block.
 *
 * This function should be called only when va_list lock is taken.
 */
static void clear_va_list_locked(struct hl_device *hdev,
		struct list_head *va_list)
{
	struct hl_vm_va_block *va_block, *tmp;

	list_for_each_entry_safe(va_block, tmp, va_list, node) {
		list_del(&va_block->node);
		kfree(va_block);
	}
}

/**
 * print_va_list_locked() - print virtual addresses list.
 * @hdev: habanalabs device structure.
 * @va_list: list of virtual addresses to print.
 *
 * This function does the following:
 * - Iterate over the list and print each virtual addresses block.
 *
 * This function should be called only when va_list lock is taken.
 */
static void print_va_list_locked(struct hl_device *hdev,
		struct list_head *va_list)
{
#if HL_MMU_DEBUG
	struct hl_vm_va_block *va_block;

	dev_dbg(hdev->dev, "print va list:\n");

	list_for_each_entry(va_block, va_list, node)
		dev_dbg(hdev->dev,
			"va block, start: 0x%llx, end: 0x%llx, size: %llu\n",
			va_block->start, va_block->end, va_block->size);
#endif
}

/**
 * merge_va_blocks_locked() - merge a virtual block if possible.
 * @hdev: pointer to the habanalabs device structure.
 * @va_list: pointer to the virtual addresses block list.
 * @va_block: virtual block to merge with adjacent blocks.
 *
 * This function does the following:
 * - Merge the given blocks with the adjacent blocks if their virtual ranges
 *   create a contiguous virtual range.
 *
 * This Function should be called only when va_list lock is taken.
 */
static void merge_va_blocks_locked(struct hl_device *hdev,
		struct list_head *va_list, struct hl_vm_va_block *va_block)
{
	struct hl_vm_va_block *prev, *next;

	prev = list_prev_entry(va_block, node);
	if (&prev->node != va_list && prev->end + 1 == va_block->start) {
		prev->end = va_block->end;
		prev->size = prev->end - prev->start + 1;
		list_del(&va_block->node);
		kfree(va_block);
		va_block = prev;
	}

	next = list_next_entry(va_block, node);
	if (&next->node != va_list && va_block->end + 1 == next->start) {
		next->start = va_block->start;
		next->size = next->end - next->start + 1;
		list_del(&va_block->node);
		kfree(va_block);
	}
}

/**
 * add_va_block_locked() - add a virtual block to the virtual addresses list.
 * @hdev: pointer to the habanalabs device structure.
 * @va_list: pointer to the virtual addresses block list.
 * @start: start virtual address.
 * @end: end virtual address.
 *
 * This function does the following:
 * - Add the given block to the virtual blocks list and merge with other blocks
 *   if a contiguous virtual block can be created.
 *
 * This Function should be called only when va_list lock is taken.
 */
static int add_va_block_locked(struct hl_device *hdev,
		struct list_head *va_list, u64 start, u64 end)
{
	struct hl_vm_va_block *va_block, *res = NULL;
	u64 size = end - start + 1;

	print_va_list_locked(hdev, va_list);

	list_for_each_entry(va_block, va_list, node) {
		/* TODO: remove upon matureness */
		if (hl_mem_area_crosses_range(start, size, va_block->start,
				va_block->end)) {
			dev_err(hdev->dev,
				"block crossing ranges at start 0x%llx, end 0x%llx\n",
				va_block->start, va_block->end);
			return -EINVAL;
		}

		if (va_block->end < start)
			res = va_block;
	}

	va_block = kmalloc(sizeof(*va_block), GFP_KERNEL);
	if (!va_block)
		return -ENOMEM;

	va_block->start = start;
	va_block->end = end;
	va_block->size = size;

	if (!res)
		list_add(&va_block->node, va_list);
	else
		list_add(&va_block->node, &res->node);

	merge_va_blocks_locked(hdev, va_list, va_block);

	print_va_list_locked(hdev, va_list);

	return 0;
}

/**
 * add_va_block() - wrapper for add_va_block_locked.
 * @hdev: pointer to the habanalabs device structure.
 * @va_range: pointer to the virtual addresses range object.
 * @start: start virtual address.
 * @end: end virtual address.
 *
 * This function does the following:
 * - Takes the list lock and calls add_va_block_locked.
 */
static inline int add_va_block(struct hl_device *hdev,
		struct hl_va_range *va_range, u64 start, u64 end)
{
	int rc;

	mutex_lock(&va_range->lock);
	rc = add_va_block_locked(hdev, &va_range->list, start, end);
	mutex_unlock(&va_range->lock);

	return rc;
}

/**
 * is_hint_crossing_range() - check if hint address crossing specified reserved.
 * @range_type: virtual space range type.
 * @start_addr: start virtual address.
 * @size: block size.
 * @prop: asic properties structure to retrieve reserved ranges from.
 */
static inline bool is_hint_crossing_range(enum hl_va_range_type range_type,
		u64 start_addr, u32 size, struct asic_fixed_properties *prop) {
	bool range_cross;

	if (range_type == HL_VA_RANGE_TYPE_DRAM)
		range_cross =
			hl_mem_area_crosses_range(start_addr, size,
			prop->hints_dram_reserved_va_range.start_addr,
			prop->hints_dram_reserved_va_range.end_addr);
	else if (range_type == HL_VA_RANGE_TYPE_HOST)
		range_cross =
			hl_mem_area_crosses_range(start_addr,	size,
			prop->hints_host_reserved_va_range.start_addr,
			prop->hints_host_reserved_va_range.end_addr);
	else
		range_cross =
			hl_mem_area_crosses_range(start_addr, size,
			prop->hints_host_hpage_reserved_va_range.start_addr,
			prop->hints_host_hpage_reserved_va_range.end_addr);

	return range_cross;
}

/**
 * get_va_block() - get a virtual block for the given size and alignment.
 *
 * @hdev: pointer to the habanalabs device structure.
 * @va_range: pointer to the virtual addresses range.
 * @size: requested block size.
 * @hint_addr: hint for requested address by the user.
 * @va_block_align: required alignment of the virtual block start address.
 * @range_type: va range type (host, dram)
 * @flags: additional memory flags, currently only uses HL_MEM_FORCE_HINT
 *
 * This function does the following:
 * - Iterate on the virtual block list to find a suitable virtual block for the
 *   given size, hint address and alignment.
 * - Reserve the requested block and update the list.
 * - Return the start address of the virtual block.
 */
static u64 get_va_block(struct hl_device *hdev,
				struct hl_va_range *va_range,
				u64 size, u64 hint_addr, u32 va_block_align,
				enum hl_va_range_type range_type,
				u32 flags)
{
	struct hl_vm_va_block *va_block, *new_va_block = NULL;
	struct asic_fixed_properties *prop = &hdev->asic_prop;
	u64 tmp_hint_addr, valid_start, valid_size, prev_start, prev_end,
		align_mask, reserved_valid_start = 0, reserved_valid_size = 0,
		dram_hint_mask = prop->dram_hints_align_mask;
	bool add_prev = false;
	bool is_align_pow_2  = is_power_of_2(va_range->page_size);
	bool is_hint_dram_addr = hl_is_dram_va(hdev, hint_addr);
	bool force_hint = flags & HL_MEM_FORCE_HINT;
	int rc;

	if (is_align_pow_2)
		align_mask = ~((u64)va_block_align - 1);
	else
		/*
		 * with non-power-of-2 range we work only with page granularity
		 * and the start address is page aligned,
		 * so no need for alignment checking.
		 */
		size = DIV_ROUND_UP_ULL(size, va_range->page_size) *
							va_range->page_size;

	tmp_hint_addr = hint_addr & ~dram_hint_mask;

	/* Check if we need to ignore hint address */
	if ((is_align_pow_2 && (hint_addr & (va_block_align - 1))) ||
			(!is_align_pow_2 && is_hint_dram_addr &&
			do_div(tmp_hint_addr, va_range->page_size))) {

		if (force_hint) {
			/* Hint must be respected, so here we just fail */
			dev_err(hdev->dev,
				"Hint address 0x%llx is not page aligned - cannot be respected\n",
				hint_addr);
			return 0;
		}

		dev_dbg(hdev->dev,
			"Hint address 0x%llx will be ignored because it is not aligned\n",
			hint_addr);
		hint_addr = 0;
	}

	mutex_lock(&va_range->lock);

	print_va_list_locked(hdev, &va_range->list);

	list_for_each_entry(va_block, &va_range->list, node) {
		/* Calc the first possible aligned addr */
		valid_start = va_block->start;

		if (is_align_pow_2 && (valid_start & (va_block_align - 1))) {
			valid_start &= align_mask;
			valid_start += va_block_align;
			if (valid_start > va_block->end)
				continue;
		}

		valid_size = va_block->end - valid_start + 1;
		if (valid_size < size)
			continue;

		/*
		 * In case hint address is 0, and hints_range_reservation
		 * property enabled, then avoid allocating va blocks from the
		 * range reserved for hint addresses
		 */
		if (prop->hints_range_reservation && !hint_addr)
			if (is_hint_crossing_range(range_type, valid_start,
					size, prop))
				continue;

		/* Pick the minimal length block which has the required size */
		if (!new_va_block || (valid_size < reserved_valid_size)) {
			new_va_block = va_block;
			reserved_valid_start = valid_start;
			reserved_valid_size = valid_size;
		}

		if (hint_addr && hint_addr >= valid_start &&
					(hint_addr + size) <= va_block->end) {
			new_va_block = va_block;
			reserved_valid_start = hint_addr;
			reserved_valid_size = valid_size;
			break;
		}
	}

	if (!new_va_block) {
		dev_err(hdev->dev, "no available va block for size %llu\n",
								size);
		goto out;
	}

	if (force_hint && reserved_valid_start != hint_addr) {
		/* Hint address must be respected. If we are here - this means
		 * we could not respect it.
		 */
		dev_err(hdev->dev,
			"Hint address 0x%llx could not be respected\n",
			hint_addr);
		reserved_valid_start = 0;
		goto out;
	}

	/*
	 * Check if there is some leftover range due to reserving the new
	 * va block, then return it to the main virtual addresses list.
	 */
	if (reserved_valid_start > new_va_block->start) {
		prev_start = new_va_block->start;
		prev_end = reserved_valid_start - 1;

		new_va_block->start = reserved_valid_start;
		new_va_block->size = reserved_valid_size;

		add_prev = true;
	}

	if (new_va_block->size > size) {
		new_va_block->start += size;
		new_va_block->size = new_va_block->end - new_va_block->start + 1;
	} else {
		list_del(&new_va_block->node);
		kfree(new_va_block);
	}

	if (add_prev) {
		rc = add_va_block_locked(hdev, &va_range->list, prev_start, prev_end);
		if (rc) {
			reserved_valid_start = 0;
			goto out;
		}
	}

	print_va_list_locked(hdev, &va_range->list);
out:
	mutex_unlock(&va_range->lock);

	return reserved_valid_start;
}

/*
 * hl_reserve_va_block() - reserve a virtual block of a given size.
 * @hdev: pointer to the habanalabs device structure.
 * @ctx: current context
 * @type: virtual addresses range type.
 * @size: requested block size.
 * @alignment: required alignment in bytes of the virtual block start address,
 *             0 means no alignment.
 *
 * This function does the following:
 * - Iterate on the virtual block list to find a suitable virtual block for the
 *   given size and alignment.
 * - Reserve the requested block and update the list.
 * - Return the start address of the virtual block.
 */
u64 hl_reserve_va_block(struct hl_device *hdev, struct hl_ctx *ctx,
		enum hl_va_range_type type, u64 size, u32 alignment)
{
	return get_va_block(hdev, ctx->va_range[type], size, 0,
			max(alignment, ctx->va_range[type]->page_size),
			type, 0);
}

/**
 * hl_get_va_range_type() - get va_range type for the given address and size.
 * @ctx: context to fetch va_range from.
 * @address: the start address of the area we want to validate.
 * @size: the size in bytes of the area we want to validate.
 * @type: returned va_range type.
 *
 * Return: true if the area is inside a valid range, false otherwise.
 */
static int hl_get_va_range_type(struct hl_ctx *ctx, u64 address, u64 size,
			enum hl_va_range_type *type)
{
	int i;

	for (i = 0 ; i < HL_VA_RANGE_TYPE_MAX; i++) {
		if (hl_mem_area_inside_range(address, size,
				ctx->va_range[i]->start_addr,
				ctx->va_range[i]->end_addr)) {
			*type = i;
			return 0;
		}
	}

	return -EINVAL;
}

/**
 * hl_unreserve_va_block() - wrapper for add_va_block to unreserve a va block.
 * @hdev: pointer to the habanalabs device structure
 * @ctx: pointer to the context structure.
 * @start_addr: start virtual address.
 * @size: number of bytes to unreserve.
 *
 * This function does the following:
 * - Takes the list lock and calls add_va_block_locked.
 */
int hl_unreserve_va_block(struct hl_device *hdev, struct hl_ctx *ctx,
		u64 start_addr, u64 size)
{
	enum hl_va_range_type type;
	int rc;

	rc = hl_get_va_range_type(ctx, start_addr, size, &type);
	if (rc) {
		dev_err(hdev->dev,
			"cannot find va_range for va %#llx size %llu",
			start_addr, size);
		return rc;
	}

	rc = add_va_block(hdev, ctx->va_range[type], start_addr,
						start_addr + size - 1);
	if (rc)
		dev_warn(hdev->dev,
			"add va block failed for vaddr: 0x%llx\n", start_addr);

	return rc;
}

/**
 * init_phys_pg_pack_from_userptr() - initialize physical page pack from host
 *                                    memory
 * @ctx: pointer to the context structure.
 * @userptr: userptr to initialize from.
 * @pphys_pg_pack: result pointer.
 * @force_regular_page: tell the function to ignore huge page optimization,
 *                      even if possible. Needed for cases where the device VA
 *                      is allocated before we know the composition of the
 *                      physical pages
 *
 * This function does the following:
 * - Create a physical page pack from the physical pages related to the given
 *   virtual block.
 */
static int init_phys_pg_pack_from_userptr(struct hl_ctx *ctx,
				struct hl_userptr *userptr,
				struct hl_vm_phys_pg_pack **pphys_pg_pack,
				bool force_regular_page)
{
	u32 npages, page_size = PAGE_SIZE,
		huge_page_size = ctx->hdev->asic_prop.pmmu_huge.page_size;
	u32 pgs_in_huge_page = huge_page_size >> __ffs(page_size);
	struct hl_vm_phys_pg_pack *phys_pg_pack;
	bool first = true, is_huge_page_opt;
	u64 page_mask, total_npages;
	struct scatterlist *sg;
	dma_addr_t dma_addr;
	int rc, i, j;

	phys_pg_pack = kzalloc(sizeof(*phys_pg_pack), GFP_KERNEL);
	if (!phys_pg_pack)
		return -ENOMEM;

	phys_pg_pack->vm_type = userptr->vm_type;
	phys_pg_pack->created_from_userptr = true;
	phys_pg_pack->asid = ctx->asid;
	atomic_set(&phys_pg_pack->mapping_cnt, 1);

	is_huge_page_opt = (force_regular_page ? false : true);

	/* Only if all dma_addrs are aligned to 2MB and their
	 * sizes is at least 2MB, we can use huge page mapping.
	 * We limit the 2MB optimization to this condition,
	 * since later on we acquire the related VA range as one
	 * consecutive block.
	 */
	total_npages = 0;
	for_each_sgtable_dma_sg(userptr->sgt, sg, i) {
		npages = hl_get_sg_info(sg, &dma_addr);

		total_npages += npages;

		if ((npages % pgs_in_huge_page) ||
					(dma_addr & (huge_page_size - 1)))
			is_huge_page_opt = false;
	}

	if (is_huge_page_opt) {
		page_size = huge_page_size;
		do_div(total_npages, pgs_in_huge_page);
	}

	page_mask = ~(((u64) page_size) - 1);

	phys_pg_pack->pages = kvmalloc_array(total_npages, sizeof(u64),
						GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(phys_pg_pack->pages)) {
		rc = -ENOMEM;
		goto page_pack_arr_mem_err;
	}

	phys_pg_pack->npages = total_npages;
	phys_pg_pack->page_size = page_size;
	phys_pg_pack->total_size = total_npages * page_size;

	j = 0;
	for_each_sgtable_dma_sg(userptr->sgt, sg, i) {
		npages = hl_get_sg_info(sg, &dma_addr);

		/* align down to physical page size and save the offset */
		if (first) {
			first = false;
			phys_pg_pack->offset = dma_addr & (page_size - 1);
			dma_addr &= page_mask;
		}

		while (npages) {
			phys_pg_pack->pages[j++] = dma_addr;
			dma_addr += page_size;

			if (is_huge_page_opt)
				npages -= pgs_in_huge_page;
			else
				npages--;
		}
	}

	*pphys_pg_pack = phys_pg_pack;

	return 0;

page_pack_arr_mem_err:
	kfree(phys_pg_pack);

	return rc;
}

/**
 * map_phys_pg_pack() - maps the physical page pack..
 * @ctx: pointer to the context structure.
 * @vaddr: start address of the virtual area to map from.
 * @phys_pg_pack: the pack of physical pages to map to.
 *
 * This function does the following:
 * - Maps each chunk of virtual memory to matching physical chunk.
 * - Stores number of successful mappings in the given argument.
 * - Returns 0 on success, error code otherwise.
 */
static int map_phys_pg_pack(struct hl_ctx *ctx, u64 vaddr,
				struct hl_vm_phys_pg_pack *phys_pg_pack)
{
	struct hl_device *hdev = ctx->hdev;
	u64 next_vaddr = vaddr, paddr, mapped_pg_cnt = 0, i;
	u32 page_size = phys_pg_pack->page_size;
	int rc = 0;
	bool is_host_addr;

	for (i = 0 ; i < phys_pg_pack->npages ; i++) {
		paddr = phys_pg_pack->pages[i];

		rc = hl_mmu_map_page(ctx, next_vaddr, paddr, page_size,
				(i + 1) == phys_pg_pack->npages);
		if (rc) {
			dev_err(hdev->dev,
				"map failed (%d) for handle %u, npages: %llu, mapped: %llu\n",
				rc, phys_pg_pack->handle, phys_pg_pack->npages,
				mapped_pg_cnt);
			goto err;
		}

		mapped_pg_cnt++;
		next_vaddr += page_size;
	}

	return 0;

err:
	is_host_addr = !hl_is_dram_va(hdev, vaddr);

	next_vaddr = vaddr;
	for (i = 0 ; i < mapped_pg_cnt ; i++) {
		if (hl_mmu_unmap_page(ctx, next_vaddr, page_size,
					(i + 1) == mapped_pg_cnt))
			dev_warn_ratelimited(hdev->dev,
				"failed to unmap handle %u, va: 0x%llx, pa: 0x%llx, page size: %u\n",
					phys_pg_pack->handle, next_vaddr,
					phys_pg_pack->pages[i], page_size);

		next_vaddr += page_size;

		/*
		 * unmapping on Palladium can be really long, so avoid a CPU
		 * soft lockup bug by sleeping a little between unmapping pages
		 *
		 * In addition, on host num of pages could be huge,
		 * because page size could be 4KB, so when unmapping host
		 * pages sleep every 32K pages to avoid soft lockup
		 */
		if (hdev->pldm || (is_host_addr && (i & 0x7FFF) == 0))
			usleep_range(50, 200);
	}

	return rc;
}

/**
 * unmap_phys_pg_pack() - unmaps the physical page pack.
 * @ctx: pointer to the context structure.
 * @vaddr: start address of the virtual area to unmap.
 * @phys_pg_pack: the pack of physical pages to unmap.
 */
static void unmap_phys_pg_pack(struct hl_ctx *ctx, u64 vaddr,
				struct hl_vm_phys_pg_pack *phys_pg_pack)
{
	struct hl_device *hdev = ctx->hdev;
	u64 next_vaddr, i;
	bool is_host_addr;
	u32 page_size;

	is_host_addr = !hl_is_dram_va(hdev, vaddr);
	page_size = phys_pg_pack->page_size;
	next_vaddr = vaddr;

	for (i = 0 ; i < phys_pg_pack->npages ; i++, next_vaddr += page_size) {
		if (hl_mmu_unmap_page(ctx, next_vaddr, page_size,
				       (i + 1) == phys_pg_pack->npages))
			dev_warn_ratelimited(hdev->dev,
			"unmap failed for vaddr: 0x%llx\n", next_vaddr);

		/*
		 * unmapping on Palladium can be really long, so avoid a CPU
		 * soft lockup bug by sleeping a little between unmapping pages
		 *
		 * In addition, on host num of pages could be huge,
		 * because page size could be 4KB, so when unmapping host
		 * pages sleep every 32K pages to avoid soft lockup
		 */
		if (hdev->pldm || (is_host_addr && (i & 0x7FFF) == 0))
			usleep_range(50, 200);
	}
}

/**
 * map_device_va() - map the given memory.
 * @ctx: pointer to the context structure.
 * @args: host parameters with handle/host virtual address.
 * @device_addr: pointer to result device virtual address.
 *
 * This function does the following:
 * - If given a physical device memory handle, map to a device virtual block
 *   and return the start address of this block.
 * - If given a host virtual address and size, find the related physical pages,
 *   map a device virtual block to this pages and return the start address of
 *   this block.
 */
static int map_device_va(struct hl_ctx *ctx, struct hl_mem_in *args, u64 *device_addr)
{
	struct hl_vm_phys_pg_pack *phys_pg_pack;
	enum hl_va_range_type va_range_type = 0;
	struct hl_device *hdev = ctx->hdev;
	struct hl_userptr *userptr = NULL;
	u32 handle = 0, va_block_align;
	struct hl_vm_hash_node *hnode;
	struct hl_vm *vm = &hdev->vm;
	struct hl_va_range *va_range;
	bool is_userptr, do_prefetch;
	u64 ret_vaddr, hint_addr;
	enum vm_type *vm_type;
	int rc;

	/* set map flags */
	is_userptr = args->flags & HL_MEM_USERPTR;
	do_prefetch = hdev->supports_mmu_prefetch && (args->flags & HL_MEM_PREFETCH);

	/* Assume failure */
	*device_addr = 0;

	if (is_userptr) {
		u64 addr = args->map_host.host_virt_addr,
			size = args->map_host.mem_size;
		u32 page_size = hdev->asic_prop.pmmu.page_size,
			huge_page_size = hdev->asic_prop.pmmu_huge.page_size;

		rc = dma_map_host_va(hdev, addr, size, &userptr);
		if (rc)
			return rc;

		rc = init_phys_pg_pack_from_userptr(ctx, userptr,
				&phys_pg_pack, false);
		if (rc) {
			dev_err(hdev->dev,
				"unable to init page pack for vaddr 0x%llx\n",
				addr);
			goto init_page_pack_err;
		}

		vm_type = (enum vm_type *) userptr;
		hint_addr = args->map_host.hint_addr;
		handle = phys_pg_pack->handle;

		/* get required alignment */
		if (phys_pg_pack->page_size == page_size) {
			va_range = ctx->va_range[HL_VA_RANGE_TYPE_HOST];
			va_range_type = HL_VA_RANGE_TYPE_HOST;
			/*
			 * huge page alignment may be needed in case of regular
			 * page mapping, depending on the host VA alignment
			 */
			if (addr & (huge_page_size - 1))
				va_block_align = page_size;
			else
				va_block_align = huge_page_size;
		} else {
			/*
			 * huge page alignment is needed in case of huge page
			 * mapping
			 */
			va_range = ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE];
			va_range_type = HL_VA_RANGE_TYPE_HOST_HUGE;
			va_block_align = huge_page_size;
		}
	} else {
		handle = lower_32_bits(args->map_device.handle);

		spin_lock(&vm->idr_lock);
		phys_pg_pack = idr_find(&vm->phys_pg_pack_handles, handle);
		if (!phys_pg_pack) {
			spin_unlock(&vm->idr_lock);
			dev_err(hdev->dev,
				"no match for handle %u\n", handle);
			return -EINVAL;
		}

		/* increment now to avoid freeing device memory while mapping */
		atomic_inc(&phys_pg_pack->mapping_cnt);

		spin_unlock(&vm->idr_lock);

		vm_type = (enum vm_type *) phys_pg_pack;

		hint_addr = args->map_device.hint_addr;

		/* DRAM VA alignment is the same as the MMU page size */
		va_range = ctx->va_range[HL_VA_RANGE_TYPE_DRAM];
		va_range_type = HL_VA_RANGE_TYPE_DRAM;
		va_block_align = hdev->asic_prop.dmmu.page_size;
	}

	/*
	 * relevant for mapping device physical memory only, as host memory is
	 * implicitly shared
	 */
	if (!is_userptr && !(phys_pg_pack->flags & HL_MEM_SHARED) &&
			phys_pg_pack->asid != ctx->asid) {
		dev_err(hdev->dev,
			"Failed to map memory, handle %u is not shared\n",
			handle);
		rc = -EPERM;
		goto shared_err;
	}

	hnode = kzalloc(sizeof(*hnode), GFP_KERNEL);
	if (!hnode) {
		rc = -ENOMEM;
		goto hnode_err;
	}

	if (hint_addr && phys_pg_pack->offset) {
		if (args->flags & HL_MEM_FORCE_HINT) {
			/* Fail if hint must be respected but it can't be */
			dev_err(hdev->dev,
				"Hint address 0x%llx cannot be respected because source memory is not aligned 0x%x\n",
				hint_addr, phys_pg_pack->offset);
			rc = -EINVAL;
			goto va_block_err;
		}
		dev_dbg(hdev->dev,
			"Hint address 0x%llx will be ignored because source memory is not aligned 0x%x\n",
			hint_addr, phys_pg_pack->offset);
	}

	ret_vaddr = get_va_block(hdev, va_range, phys_pg_pack->total_size,
					hint_addr, va_block_align,
					va_range_type, args->flags);
	if (!ret_vaddr) {
		dev_err(hdev->dev, "no available va block for handle %u\n",
				handle);
		rc = -ENOMEM;
		goto va_block_err;
	}

	mutex_lock(&hdev->mmu_lock);

	rc = map_phys_pg_pack(ctx, ret_vaddr, phys_pg_pack);
	if (rc) {
		dev_err(hdev->dev, "mapping page pack failed (%d) for handle %u\n",
			rc, handle);
		mutex_unlock(&hdev->mmu_lock);
		goto map_err;
	}

	rc = hl_mmu_invalidate_cache_range(hdev, false, *vm_type | MMU_OP_SKIP_LOW_CACHE_INV,
				ctx->asid, ret_vaddr, phys_pg_pack->total_size);
	mutex_unlock(&hdev->mmu_lock);
	if (rc)
		goto map_err;

	/*
	 * prefetch is done upon user's request. it is performed in WQ as and so can
	 * be outside the MMU lock. the operation itself is already protected by the mmu lock
	 */
	if (do_prefetch) {
		rc = hl_mmu_prefetch_cache_range(ctx, *vm_type, ctx->asid, ret_vaddr,
							phys_pg_pack->total_size);
		if (rc)
			goto map_err;
	}

	ret_vaddr += phys_pg_pack->offset;

	hnode->ptr = vm_type;
	hnode->vaddr = ret_vaddr;
	hnode->handle = is_userptr ? MEM_HANDLE_INVALID : handle;

	mutex_lock(&ctx->mem_hash_lock);
	hash_add(ctx->mem_hash, &hnode->node, ret_vaddr);
	mutex_unlock(&ctx->mem_hash_lock);

	*device_addr = ret_vaddr;

	if (is_userptr)
		free_phys_pg_pack(hdev, phys_pg_pack);

	return rc;

map_err:
	if (add_va_block(hdev, va_range, ret_vaddr,
				ret_vaddr + phys_pg_pack->total_size - 1))
		dev_warn(hdev->dev,
			"release va block failed for handle 0x%x, vaddr: 0x%llx\n",
				handle, ret_vaddr);

va_block_err:
	kfree(hnode);
hnode_err:
shared_err:
	atomic_dec(&phys_pg_pack->mapping_cnt);
	if (is_userptr)
		free_phys_pg_pack(hdev, phys_pg_pack);
init_page_pack_err:
	if (is_userptr)
		dma_unmap_host_va(hdev, userptr);

	return rc;
}

/* Should be called while the context's mem_hash_lock is taken */
static struct hl_vm_hash_node *get_vm_hash_node_locked(struct hl_ctx *ctx, u64 vaddr)
{
	struct hl_vm_hash_node *hnode;

	hash_for_each_possible(ctx->mem_hash, hnode, node, vaddr)
		if (vaddr == hnode->vaddr)
			return hnode;

	return NULL;
}

/**
 * unmap_device_va() - unmap the given device virtual address.
 * @ctx: pointer to the context structure.
 * @args: host parameters with device virtual address to unmap.
 * @ctx_free: true if in context free flow, false otherwise.
 *
 * This function does the following:
 * - unmap the physical pages related to the given virtual address.
 * - return the device virtual block to the virtual block list.
 */
static int unmap_device_va(struct hl_ctx *ctx, struct hl_mem_in *args,
				bool ctx_free)
{
	struct hl_vm_phys_pg_pack *phys_pg_pack = NULL;
	u64 vaddr = args->unmap.device_virt_addr;
	struct asic_fixed_properties *prop;
	struct hl_device *hdev = ctx->hdev;
	struct hl_userptr *userptr = NULL;
	struct hl_vm_hash_node *hnode;
	struct hl_va_range *va_range;
	enum vm_type *vm_type;
	bool is_userptr;
	int rc = 0;

	prop = &hdev->asic_prop;

	/* protect from double entrance */
	mutex_lock(&ctx->mem_hash_lock);
	hnode = get_vm_hash_node_locked(ctx, vaddr);
	if (!hnode) {
		mutex_unlock(&ctx->mem_hash_lock);
		dev_err(hdev->dev, "unmap failed, no mem hnode for vaddr 0x%llx\n", vaddr);
		return -EINVAL;
	}

	if (hnode->export_cnt) {
		mutex_unlock(&ctx->mem_hash_lock);
		dev_err(hdev->dev, "failed to unmap %#llx, memory is exported\n", vaddr);
		return -EINVAL;
	}

	hash_del(&hnode->node);
	mutex_unlock(&ctx->mem_hash_lock);

	vm_type = hnode->ptr;

	if (*vm_type == VM_TYPE_USERPTR) {
		is_userptr = true;
		userptr = hnode->ptr;

		rc = init_phys_pg_pack_from_userptr(ctx, userptr, &phys_pg_pack,
							false);
		if (rc) {
			dev_err(hdev->dev,
				"unable to init page pack for vaddr 0x%llx\n",
				vaddr);
			goto vm_type_err;
		}

		if (phys_pg_pack->page_size ==
					hdev->asic_prop.pmmu.page_size)
			va_range = ctx->va_range[HL_VA_RANGE_TYPE_HOST];
		else
			va_range = ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE];
	} else if (*vm_type == VM_TYPE_PHYS_PACK) {
		is_userptr = false;
		va_range = ctx->va_range[HL_VA_RANGE_TYPE_DRAM];
		phys_pg_pack = hnode->ptr;
	} else {
		dev_warn(hdev->dev,
			"unmap failed, unknown vm desc for vaddr 0x%llx\n",
				vaddr);
		rc = -EFAULT;
		goto vm_type_err;
	}

	if (atomic_read(&phys_pg_pack->mapping_cnt) == 0) {
		dev_err(hdev->dev, "vaddr 0x%llx is not mapped\n", vaddr);
		rc = -EINVAL;
		goto mapping_cnt_err;
	}

	if (!is_userptr && !is_power_of_2(phys_pg_pack->page_size))
		vaddr = prop->dram_base_address +
			DIV_ROUND_DOWN_ULL(vaddr - prop->dram_base_address,
						phys_pg_pack->page_size) *
							phys_pg_pack->page_size;
	else
		vaddr &= ~(((u64) phys_pg_pack->page_size) - 1);

	mutex_lock(&hdev->mmu_lock);

	unmap_phys_pg_pack(ctx, vaddr, phys_pg_pack);

	/*
	 * During context free this function is called in a loop to clean all
	 * the context mappings. Hence the cache invalidation can be called once
	 * at the loop end rather than for each iteration
	 */
	if (!ctx_free)
		rc = hl_mmu_invalidate_cache_range(hdev, true, *vm_type, ctx->asid, vaddr,
							phys_pg_pack->total_size);

	mutex_unlock(&hdev->mmu_lock);

	/*
	 * If the context is closing we don't need to check for the MMU cache
	 * invalidation return code and update the VA free list as in this flow
	 * we invalidate the MMU cache outside of this unmap function and the VA
	 * free list will be freed anyway.
	 */
	if (!ctx_free) {
		int tmp_rc;

		tmp_rc = add_va_block(hdev, va_range, vaddr,
					vaddr + phys_pg_pack->total_size - 1);
		if (tmp_rc) {
			dev_warn(hdev->dev,
					"add va block failed for vaddr: 0x%llx\n",
					vaddr);
			if (!rc)
				rc = tmp_rc;
		}
	}

	atomic_dec(&phys_pg_pack->mapping_cnt);
	kfree(hnode);

	if (is_userptr) {
		free_phys_pg_pack(hdev, phys_pg_pack);
		dma_unmap_host_va(hdev, userptr);
	}

	return rc;

mapping_cnt_err:
	if (is_userptr)
		free_phys_pg_pack(hdev, phys_pg_pack);
vm_type_err:
	mutex_lock(&ctx->mem_hash_lock);
	hash_add(ctx->mem_hash, &hnode->node, vaddr);
	mutex_unlock(&ctx->mem_hash_lock);

	return rc;
}

static int map_block(struct hl_device *hdev, u64 address, u64 *handle, u32 *size)
{
	u32 block_id;
	int rc;

	*handle = 0;
	if (size)
		*size = 0;

	rc = hdev->asic_funcs->get_hw_block_id(hdev, address, size, &block_id);
	if (rc)
		return rc;

	*handle = block_id | HL_MMAP_TYPE_BLOCK;
	*handle <<= PAGE_SHIFT;

	return 0;
}

static void hw_block_vm_close(struct vm_area_struct *vma)
{
	struct hl_vm_hw_block_list_node *lnode =
		(struct hl_vm_hw_block_list_node *) vma->vm_private_data;
	struct hl_ctx *ctx = lnode->ctx;
	long new_mmap_size;

	new_mmap_size = lnode->mapped_size - (vma->vm_end - vma->vm_start);
	if (new_mmap_size > 0) {
		lnode->mapped_size = new_mmap_size;
		return;
	}

	mutex_lock(&ctx->hw_block_list_lock);
	list_del(&lnode->node);
	mutex_unlock(&ctx->hw_block_list_lock);
	hl_ctx_put(ctx);
	kfree(lnode);
	vma->vm_private_data = NULL;
}

static const struct vm_operations_struct hw_block_vm_ops = {
	.close = hw_block_vm_close
};

/**
 * hl_hw_block_mmap() - mmap a hw block to user.
 * @hpriv: pointer to the private data of the fd
 * @vma: pointer to vm_area_struct of the process
 *
 * Driver increments context reference for every HW block mapped in order
 * to prevent user from closing FD without unmapping first
 */
int hl_hw_block_mmap(struct hl_fpriv *hpriv, struct vm_area_struct *vma)
{
	struct hl_vm_hw_block_list_node *lnode;
	struct hl_device *hdev = hpriv->hdev;
	struct hl_ctx *ctx = hpriv->ctx;
	u32 block_id, block_size;
	int rc;

	/* We use the page offset to hold the block id and thus we need to clear
	 * it before doing the mmap itself
	 */
	block_id = vma->vm_pgoff;
	vma->vm_pgoff = 0;

	/* Driver only allows mapping of a complete HW block */
	block_size = vma->vm_end - vma->vm_start;

	if (!access_ok((void __user *) (uintptr_t) vma->vm_start, block_size)) {
		dev_err(hdev->dev,
			"user pointer is invalid - 0x%lx\n",
			vma->vm_start);

		return -EINVAL;
	}

	lnode = kzalloc(sizeof(*lnode), GFP_KERNEL);
	if (!lnode)
		return -ENOMEM;

	rc = hdev->asic_funcs->hw_block_mmap(hdev, vma, block_id, block_size);
	if (rc) {
		kfree(lnode);
		return rc;
	}

	hl_ctx_get(ctx);

	lnode->ctx = ctx;
	lnode->vaddr = vma->vm_start;
	lnode->block_size = block_size;
	lnode->mapped_size = lnode->block_size;
	lnode->id = block_id;

	vma->vm_private_data = lnode;
	vma->vm_ops = &hw_block_vm_ops;

	mutex_lock(&ctx->hw_block_list_lock);
	list_add_tail(&lnode->node, &ctx->hw_block_mem_list);
	mutex_unlock(&ctx->hw_block_list_lock);

	vma->vm_pgoff = block_id;

	return 0;
}

static int set_dma_sg(struct scatterlist *sg, u64 bar_address, u64 chunk_size,
			struct device *dev, enum dma_data_direction dir)
{
	dma_addr_t addr;
	int rc;

	addr = dma_map_resource(dev, bar_address, chunk_size, dir,
				DMA_ATTR_SKIP_CPU_SYNC);
	rc = dma_mapping_error(dev, addr);
	if (rc)
		return rc;

	sg_set_page(sg, NULL, chunk_size, 0);
	sg_dma_address(sg) = addr;
	sg_dma_len(sg) = chunk_size;

	return 0;
}

static struct sg_table *alloc_sgt_from_device_pages(struct hl_device *hdev, u64 *pages, u64 npages,
						u64 page_size, u64 exported_size, u64 offset,
						struct device *dev, enum dma_data_direction dir)
{
	u64 dma_max_seg_size, curr_page, size, chunk_size, left_size_to_export, left_size_in_page,
		left_size_in_dma_seg, device_address, bar_address, start_page;
	struct asic_fixed_properties *prop = &hdev->asic_prop;
	struct scatterlist *sg;
	unsigned int nents, i;
	struct sg_table *sgt;
	bool next_sg_entry;
	int rc;

	/* Align max segment size to PAGE_SIZE to fit the minimal IOMMU mapping granularity */
	dma_max_seg_size = ALIGN_DOWN(dma_get_max_seg_size(dev), PAGE_SIZE);
	if (dma_max_seg_size < PAGE_SIZE) {
		dev_err_ratelimited(hdev->dev,
				"dma_max_seg_size %llu can't be smaller than PAGE_SIZE\n",
				dma_max_seg_size);
		return ERR_PTR(-EINVAL);
	}

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	/* Use the offset to move to the actual first page that is exported */
	for (start_page = 0 ; start_page < npages ; ++start_page) {
		if (offset < page_size)
			break;

		/* The offset value was validated so there can't be an underflow */
		offset -= page_size;
	}

	/* Calculate the required number of entries for the SG table */
	curr_page = start_page;
	nents = 1;
	left_size_to_export = exported_size;
	left_size_in_page = page_size - offset;
	left_size_in_dma_seg = dma_max_seg_size;
	next_sg_entry = false;

	while (true) {
		size = min3(left_size_to_export, left_size_in_page, left_size_in_dma_seg);
		left_size_to_export -= size;
		left_size_in_page -= size;
		left_size_in_dma_seg -= size;

		if (!left_size_to_export)
			break;

		if (!left_size_in_page) {
			/* left_size_to_export is not zero so there must be another page */
			if (pages[curr_page] + page_size != pages[curr_page + 1])
				next_sg_entry = true;

			++curr_page;
			left_size_in_page = page_size;
		}

		if (!left_size_in_dma_seg) {
			next_sg_entry = true;
			left_size_in_dma_seg = dma_max_seg_size;
		}

		if (next_sg_entry) {
			++nents;
			next_sg_entry = false;
		}
	}

	rc = sg_alloc_table(sgt, nents, GFP_KERNEL | __GFP_ZERO);
	if (rc)
		goto err_free_sgt;

	/* Prepare the SG table entries */
	curr_page = start_page;
	device_address = pages[curr_page] + offset;
	left_size_to_export = exported_size;
	left_size_in_page = page_size - offset;
	left_size_in_dma_seg = dma_max_seg_size;
	next_sg_entry = false;

	for_each_sgtable_dma_sg(sgt, sg, i) {
		bar_address = hdev->dram_pci_bar_start + (device_address - prop->dram_base_address);
		chunk_size = 0;

		for ( ; curr_page < npages ; ++curr_page) {
			size = min3(left_size_to_export, left_size_in_page, left_size_in_dma_seg);
			chunk_size += size;
			left_size_to_export -= size;
			left_size_in_page -= size;
			left_size_in_dma_seg -= size;

			if (!left_size_to_export)
				break;

			if (!left_size_in_page) {
				/* left_size_to_export is not zero so there must be another page */
				if (pages[curr_page] + page_size != pages[curr_page + 1]) {
					device_address = pages[curr_page + 1];
					next_sg_entry = true;
				}

				left_size_in_page = page_size;
			}

			if (!left_size_in_dma_seg) {
				/*
				 * Skip setting a new device address if already moving to a page
				 * which is not contiguous with the current page.
				 */
				if (!next_sg_entry) {
					device_address += chunk_size;
					next_sg_entry = true;
				}

				left_size_in_dma_seg = dma_max_seg_size;
			}

			if (next_sg_entry) {
				next_sg_entry = false;
				break;
			}
		}

		rc = set_dma_sg(sg, bar_address, chunk_size, dev, dir);
		if (rc)
			goto err_unmap;
	}

	/* There should be nothing left to export exactly after looping over all SG elements */
	if (left_size_to_export) {
		dev_err(hdev->dev,
			"left size to export %#llx after initializing %u SG elements\n",
			left_size_to_export, sgt->nents);
		rc = -ENOMEM;
		goto err_unmap;
	}

	/*
	 * Because we are not going to include a CPU list, we want to have some chance that other
	 * users will detect this when going over SG table, by setting the orig_nents to 0 and using
	 * only nents (length of DMA list).
	 */
	sgt->orig_nents = 0;

	dev_dbg(hdev->dev, "prepared SG table with %u entries for importer %s\n",
		nents, dev_name(dev));
	for_each_sgtable_dma_sg(sgt, sg, i)
		dev_dbg(hdev->dev,
			"SG entry %d: address %#llx, length %#x\n",
			i, sg_dma_address(sg), sg_dma_len(sg));

	return sgt;

err_unmap:
	for_each_sgtable_dma_sg(sgt, sg, i) {
		if (!sg_dma_len(sg))
			continue;

		dma_unmap_resource(dev, sg_dma_address(sg), sg_dma_len(sg), dir,
					DMA_ATTR_SKIP_CPU_SYNC);
	}

	sg_free_table(sgt);

err_free_sgt:
	kfree(sgt);
	return ERR_PTR(rc);
}

static int hl_dmabuf_attach(struct dma_buf *dmabuf,
				struct dma_buf_attachment *attachment)
{
	struct hl_dmabuf_priv *hl_dmabuf;
	struct hl_device *hdev;
	int rc;

	hl_dmabuf = dmabuf->priv;
	hdev = hl_dmabuf->ctx->hdev;

	rc = pci_p2pdma_distance(hdev->pdev, attachment->dev, true);

	if (rc < 0)
		attachment->peer2peer = false;
	return 0;
}

static struct sg_table *hl_map_dmabuf(struct dma_buf_attachment *attachment,
					enum dma_data_direction dir)
{
	u64 *pages, npages, page_size, exported_size, offset;
	struct dma_buf *dma_buf = attachment->dmabuf;
	struct hl_vm_phys_pg_pack *phys_pg_pack;
	struct hl_dmabuf_priv *hl_dmabuf;
	struct hl_device *hdev;
	struct sg_table *sgt;

	hl_dmabuf = dma_buf->priv;
	hdev = hl_dmabuf->ctx->hdev;

	if (!attachment->peer2peer) {
		dev_dbg(hdev->dev, "Failed to map dmabuf because p2p is disabled\n");
		return ERR_PTR(-EPERM);
	}

	exported_size = hl_dmabuf->dmabuf->size;
	offset = hl_dmabuf->offset;
	phys_pg_pack = hl_dmabuf->phys_pg_pack;

	if (phys_pg_pack) {
		pages = phys_pg_pack->pages;
		npages = phys_pg_pack->npages;
		page_size = phys_pg_pack->page_size;
	} else {
		pages = &hl_dmabuf->device_phys_addr;
		npages = 1;
		page_size = hl_dmabuf->dmabuf->size;
	}

	sgt = alloc_sgt_from_device_pages(hdev, pages, npages, page_size, exported_size, offset,
						attachment->dev, dir);
	if (IS_ERR(sgt))
		dev_err(hdev->dev, "failed (%ld) to initialize sgt for dmabuf\n", PTR_ERR(sgt));

	return sgt;
}

static void hl_unmap_dmabuf(struct dma_buf_attachment *attachment,
				  struct sg_table *sgt,
				  enum dma_data_direction dir)
{
	struct scatterlist *sg;
	int i;

	/* The memory behind the dma-buf has *always* resided on the device itself, i.e. it lives
	 * only in the 'device' domain (after all, it maps a PCI bar address which points to the
	 * device memory).
	 *
	 * Therefore, it was never in the 'CPU' domain and hence, there is no need to perform
	 * a sync of the memory to the CPU's cache, as it never resided inside that cache.
	 */
	for_each_sgtable_dma_sg(sgt, sg, i)
		dma_unmap_resource(attachment->dev, sg_dma_address(sg),
					sg_dma_len(sg), dir,
					DMA_ATTR_SKIP_CPU_SYNC);

	/* Need to restore orig_nents because sg_free_table use that field */
	sgt->orig_nents = sgt->nents;
	sg_free_table(sgt);
	kfree(sgt);
}

static struct hl_vm_hash_node *memhash_node_export_get(struct hl_ctx *ctx, u64 addr)
{
	struct hl_device *hdev = ctx->hdev;
	struct hl_vm_hash_node *hnode;

	/* get the memory handle */
	mutex_lock(&ctx->mem_hash_lock);
	hnode = get_vm_hash_node_locked(ctx, addr);
	if (!hnode) {
		mutex_unlock(&ctx->mem_hash_lock);
		dev_dbg(hdev->dev, "map address %#llx not found\n", addr);
		return ERR_PTR(-EINVAL);
	}

	if (upper_32_bits(hnode->handle)) {
		mutex_unlock(&ctx->mem_hash_lock);
		dev_dbg(hdev->dev, "invalid handle %#llx for map address %#llx\n",
				hnode->handle, addr);
		return ERR_PTR(-EINVAL);
	}

	/*
	 * node found, increase export count so this memory cannot be unmapped
	 * and the hash node cannot be deleted.
	 */
	hnode->export_cnt++;
	mutex_unlock(&ctx->mem_hash_lock);

	return hnode;
}

static void memhash_node_export_put(struct hl_ctx *ctx, struct hl_vm_hash_node *hnode)
{
	mutex_lock(&ctx->mem_hash_lock);
	hnode->export_cnt--;
	mutex_unlock(&ctx->mem_hash_lock);
}

static void hl_release_dmabuf(struct dma_buf *dmabuf)
{
	struct hl_dmabuf_priv *hl_dmabuf = dmabuf->priv;
	struct hl_ctx *ctx;

	ctx = hl_dmabuf->ctx;

	if (hl_dmabuf->memhash_hnode)
		memhash_node_export_put(ctx, hl_dmabuf->memhash_hnode);

	atomic_dec(&ctx->hdev->dmabuf_export_cnt);
	hl_ctx_put(ctx);

	/* Paired with get_file() in export_dmabuf() */
	fput(ctx->hpriv->file_priv->filp);

	kfree(hl_dmabuf);
}

static const struct dma_buf_ops habanalabs_dmabuf_ops = {
	.attach = hl_dmabuf_attach,
	.map_dma_buf = hl_map_dmabuf,
	.unmap_dma_buf = hl_unmap_dmabuf,
	.release = hl_release_dmabuf,
};

static int export_dmabuf(struct hl_ctx *ctx,
				struct hl_dmabuf_priv *hl_dmabuf,
				u64 total_size, int flags, int *dmabuf_fd)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct hl_device *hdev = ctx->hdev;
	CLASS(get_unused_fd, fd)(flags);

	if (fd < 0) {
		dev_err(hdev->dev, "failed to get a file descriptor for a dma-buf, %d\n", fd);
		return fd;
	}

	exp_info.ops = &habanalabs_dmabuf_ops;
	exp_info.size = total_size;
	exp_info.flags = flags;
	exp_info.priv = hl_dmabuf;

	hl_dmabuf->dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(hl_dmabuf->dmabuf)) {
		dev_err(hdev->dev, "failed to export dma-buf\n");
		return PTR_ERR(hl_dmabuf->dmabuf);
	}

	hl_dmabuf->ctx = ctx;
	hl_ctx_get(hl_dmabuf->ctx);
	atomic_inc(&ctx->hdev->dmabuf_export_cnt);

	/* Get compute device file to enforce release order, such that all exported dma-buf will be
	 * released first and only then the compute device.
	 * Paired with fput() in hl_release_dmabuf().
	 */
	get_file(ctx->hpriv->file_priv->filp);

	*dmabuf_fd = fd;
	fd_install(take_fd(fd), hl_dmabuf->dmabuf->file);

	return 0;
}

static int validate_export_params_common(struct hl_device *hdev, u64 addr, u64 size, u64 offset)
{
	if (!PAGE_ALIGNED(addr)) {
		dev_dbg(hdev->dev,
			"exported device memory address 0x%llx should be aligned to PAGE_SIZE 0x%lx\n",
			addr, PAGE_SIZE);
		return -EINVAL;
	}

	if (!size || !PAGE_ALIGNED(size)) {
		dev_dbg(hdev->dev,
			"exported device memory size %llu should be a multiple of PAGE_SIZE %lu\n",
			size, PAGE_SIZE);
		return -EINVAL;
	}

	if (!PAGE_ALIGNED(offset)) {
		dev_dbg(hdev->dev,
			"exported device memory offset %llu should be a multiple of PAGE_SIZE %lu\n",
			offset, PAGE_SIZE);
		return -EINVAL;
	}

	return 0;
}

static int validate_export_params_no_mmu(struct hl_device *hdev, u64 device_addr, u64 size)
{
	struct asic_fixed_properties *prop = &hdev->asic_prop;
	u64 bar_address;
	int rc;

	rc = validate_export_params_common(hdev, device_addr, size, 0);
	if (rc)
		return rc;

	if (device_addr < prop->dram_user_base_address ||
			(device_addr + size) > prop->dram_end_address ||
			(device_addr + size) < device_addr) {
		dev_dbg(hdev->dev,
			"DRAM memory range 0x%llx (+0x%llx) is outside of DRAM boundaries\n",
			device_addr, size);
		return -EINVAL;
	}

	bar_address = hdev->dram_pci_bar_start + (device_addr - prop->dram_base_address);

	if ((bar_address + size) > (hdev->dram_pci_bar_start + prop->dram_pci_bar_size) ||
			(bar_address + size) < bar_address) {
		dev_dbg(hdev->dev,
			"DRAM memory range 0x%llx (+0x%llx) is outside of PCI BAR boundaries\n",
			device_addr, size);
		return -EINVAL;
	}

	return 0;
}

static int validate_export_params(struct hl_device *hdev, u64 device_addr, u64 size, u64 offset,
					struct hl_vm_phys_pg_pack *phys_pg_pack)
{
	struct asic_fixed_properties *prop = &hdev->asic_prop;
	u64 bar_address;
	int i, rc;

	rc = validate_export_params_common(hdev, device_addr, size, offset);
	if (rc)
		return rc;

	if ((offset + size) > phys_pg_pack->total_size) {
		dev_dbg(hdev->dev, "offset %#llx and size %#llx exceed total map size %#llx\n",
			offset, size, phys_pg_pack->total_size);
		return -EINVAL;
	}

	for (i = 0 ; i < phys_pg_pack->npages ; i++) {
		bar_address = hdev->dram_pci_bar_start +
				(phys_pg_pack->pages[i] - prop->dram_base_address);

		if ((bar_address + phys_pg_pack->page_size) >
				(hdev->dram_pci_bar_start + prop->dram_pci_bar_size) ||
				(bar_address + phys_pg_pack->page_size) < bar_address) {
			dev_dbg(hdev->dev,
				"DRAM memory range 0x%llx (+0x%x) is outside of PCI BAR boundaries\n",
				phys_pg_pack->pages[i], phys_pg_pack->page_size);
			return -EINVAL;
		}
	}

	return 0;
}

static struct hl_vm_phys_pg_pack *get_phys_pg_pack_from_hash_node(struct hl_device *hdev,
							struct hl_vm_hash_node *hnode)
{
	struct hl_vm_phys_pg_pack *phys_pg_pack;
	struct hl_vm *vm = &hdev->vm;

	spin_lock(&vm->idr_lock);
	phys_pg_pack = idr_find(&vm->phys_pg_pack_handles, (u32) hnode->handle);
	if (!phys_pg_pack) {
		spin_unlock(&vm->idr_lock);
		dev_dbg(hdev->dev, "no match for handle 0x%x\n", (u32) hnode->handle);
		return ERR_PTR(-EINVAL);
	}

	spin_unlock(&vm->idr_lock);

	if (phys_pg_pack->vm_type != VM_TYPE_PHYS_PACK) {
		dev_dbg(hdev->dev, "handle 0x%llx does not represent DRAM memory\n", hnode->handle);
		return ERR_PTR(-EINVAL);
	}

	return phys_pg_pack;
}

/**
 * export_dmabuf_from_addr() - export a dma-buf object for the given memory
 *                             address and size.
 * @ctx: pointer to the context structure.
 * @addr: device address.
 * @size: size of device memory to export.
 * @offset: the offset into the buffer from which to start exporting
 * @flags: DMA-BUF file/FD flags.
 * @dmabuf_fd: pointer to result FD that represents the dma-buf object.
 *
 * Create and export a dma-buf object for an existing memory allocation inside
 * the device memory, and return a FD which is associated with the dma-buf
 * object.
 *
 * Return: 0 on success, non-zero for failure.
 */
static int export_dmabuf_from_addr(struct hl_ctx *ctx, u64 addr, u64 size, u64 offset,
					int flags, int *dmabuf_fd)
{
	struct hl_vm_phys_pg_pack *phys_pg_pack = NULL;
	struct hl_vm_hash_node *hnode = NULL;
	struct asic_fixed_properties *prop;
	struct hl_dmabuf_priv *hl_dmabuf;
	struct hl_device *hdev;
	int rc;

	hdev = ctx->hdev;
	prop = &hdev->asic_prop;

	/* offset must be 0 in devices without virtual memory support */
	if (!prop->dram_supports_virtual_memory && offset) {
		dev_dbg(hdev->dev, "offset is not allowed in device without virtual memory\n");
		return -EINVAL;
	}

	hl_dmabuf = kzalloc(sizeof(*hl_dmabuf), GFP_KERNEL);
	if (!hl_dmabuf)
		return -ENOMEM;

	if (prop->dram_supports_virtual_memory) {
		hnode = memhash_node_export_get(ctx, addr);
		if (IS_ERR(hnode)) {
			rc = PTR_ERR(hnode);
			goto err_free_dmabuf_wrapper;
		}
		phys_pg_pack = get_phys_pg_pack_from_hash_node(hdev, hnode);
		if (IS_ERR(phys_pg_pack)) {
			rc = PTR_ERR(phys_pg_pack);
			goto dec_memhash_export_cnt;
		}
		rc = validate_export_params(hdev, addr, size, offset, phys_pg_pack);
		if (rc)
			goto dec_memhash_export_cnt;

		hl_dmabuf->phys_pg_pack = phys_pg_pack;
		hl_dmabuf->memhash_hnode = hnode;
		hl_dmabuf->offset = offset;
	} else {
		rc = validate_export_params_no_mmu(hdev, addr, size);
		if (rc)
			goto err_free_dmabuf_wrapper;

		hl_dmabuf->device_phys_addr = addr;
	}

	rc = export_dmabuf(ctx, hl_dmabuf, size, flags, dmabuf_fd);
	if (rc)
		goto dec_memhash_export_cnt;

	return 0;

dec_memhash_export_cnt:
	if (prop->dram_supports_virtual_memory)
		memhash_node_export_put(ctx, hnode);
err_free_dmabuf_wrapper:
	kfree(hl_dmabuf);
	return rc;
}

static void ts_buff_release(struct hl_mmap_mem_buf *buf)
{
	struct hl_ts_buff *ts_buff = buf->private;

	vfree(ts_buff->kernel_buff_address);
	vfree(ts_buff->user_buff_address);
	kfree(ts_buff);
}

static int hl_ts_mmap(struct hl_mmap_mem_buf *buf, struct vm_area_struct *vma, void *args)
{
	struct hl_ts_buff *ts_buff = buf->private;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY | VM_NORESERVE);
	return remap_vmalloc_range(vma, ts_buff->user_buff_address, 0);
}

static int hl_ts_alloc_buf(struct hl_mmap_mem_buf *buf, gfp_t gfp, void *args)
{
	struct hl_ts_buff *ts_buff = NULL;
	u32 num_elements;
	size_t size;
	void *p;

	num_elements = *(u32 *)args;

	ts_buff = kzalloc(sizeof(*ts_buff), gfp);
	if (!ts_buff)
		return -ENOMEM;

	/* Allocate the user buffer */
	size = num_elements * sizeof(u64);
	p = vmalloc_user(size);
	if (!p)
		goto free_mem;

	ts_buff->user_buff_address = p;
	buf->mappable_size = size;

	/* Allocate the internal kernel buffer */
	size = num_elements * sizeof(struct hl_user_pending_interrupt);
	p = vzalloc(size);
	if (!p)
		goto free_user_buff;

	ts_buff->kernel_buff_address = p;
	ts_buff->kernel_buff_size = size;

	buf->private = ts_buff;

	return 0;

free_user_buff:
	vfree(ts_buff->user_buff_address);
free_mem:
	kfree(ts_buff);
	return -ENOMEM;
}

static struct hl_mmap_mem_buf_behavior hl_ts_behavior = {
	.topic = "TS",
	.mem_id = HL_MMAP_TYPE_TS_BUFF,
	.mmap = hl_ts_mmap,
	.alloc = hl_ts_alloc_buf,
	.release = ts_buff_release,
};

/**
 * allocate_timestamps_buffers() - allocate timestamps buffers
 * This function will allocate ts buffer that will later on be mapped to the user
 * in order to be able to read the timestamp.
 * in addition it'll allocate an extra buffer for registration management.
 * since we cannot fail during registration for out-of-memory situation, so
 * we'll prepare a pool which will be used as user interrupt nodes and instead
 * of dynamically allocating nodes while registration we'll pick the node from
 * this pool. in addition it'll add node to the mapping hash which will be used
 * to map user ts buffer to the internal kernel ts buffer.
 * @hpriv: pointer to the private data of the fd
 * @args: ioctl input
 * @handle: user timestamp buffer handle as an output
 */
static int allocate_timestamps_buffers(struct hl_fpriv *hpriv, struct hl_mem_in *args, u64 *handle)
{
	struct hl_mem_mgr *mmg = &hpriv->mem_mgr;
	struct hl_mmap_mem_buf *buf;

	if (args->num_of_elements > TS_MAX_ELEMENTS_NUM) {
		dev_err(mmg->dev, "Num of elements exceeds Max allowed number (0x%x > 0x%x)\n",
				args->num_of_elements, TS_MAX_ELEMENTS_NUM);
		return -EINVAL;
	}

	buf = hl_mmap_mem_buf_alloc(mmg, &hl_ts_behavior, GFP_KERNEL, &args->num_of_elements);
	if (!buf)
		return -ENOMEM;

	*handle = buf->handle;

	return 0;
}

int hl_mem_ioctl(struct drm_device *ddev, void *data, struct drm_file *file_priv)
{
	struct hl_fpriv *hpriv = file_priv->driver_priv;
	enum hl_device_status status;
	union hl_mem_args *args = data;
	struct hl_device *hdev = hpriv->hdev;
	struct hl_ctx *ctx = hpriv->ctx;
	u64 block_handle, device_addr = 0;
	u32 handle = 0, block_size;
	int rc, dmabuf_fd = -EBADF;

	if (!hl_device_operational(hdev, &status)) {
		dev_dbg_ratelimited(hdev->dev,
			"Device is %s. Can't execute MEMORY IOCTL\n",
			hdev->status[status]);
		return -EBUSY;
	}

	switch (args->in.op) {
	case HL_MEM_OP_ALLOC:
		if (args->in.alloc.mem_size == 0) {
			dev_err(hdev->dev,
				"alloc size must be larger than 0\n");
			rc = -EINVAL;
			goto out;
		}

		/* If DRAM does not support virtual memory the driver won't
		 * handle the allocation/freeing of that memory. However, for
		 * system administration/monitoring purposes, the driver will
		 * keep track of the amount of DRAM memory that is allocated
		 * and freed by the user. Because this code totally relies on
		 * the user's input, the driver can't ensure the validity
		 * of this accounting.
		 */
		if (!hdev->asic_prop.dram_supports_virtual_memory) {
			atomic64_add(args->in.alloc.mem_size,
					&ctx->dram_phys_mem);
			atomic64_add(args->in.alloc.mem_size,
					&hdev->dram_used_mem);

			dev_dbg(hdev->dev, "DRAM alloc is not supported\n");
			rc = 0;

			memset(args, 0, sizeof(*args));
			args->out.handle = 0;
			goto out;
		}

		rc = alloc_device_memory(ctx, &args->in, &handle);

		memset(args, 0, sizeof(*args));
		args->out.handle = (__u64) handle;
		break;

	case HL_MEM_OP_FREE:
		/* If DRAM does not support virtual memory the driver won't
		 * handle the allocation/freeing of that memory. However, for
		 * system administration/monitoring purposes, the driver will
		 * keep track of the amount of DRAM memory that is allocated
		 * and freed by the user. Because this code totally relies on
		 * the user's input, the driver can't ensure the validity
		 * of this accounting.
		 */
		if (!hdev->asic_prop.dram_supports_virtual_memory) {
			atomic64_sub(args->in.alloc.mem_size,
					&ctx->dram_phys_mem);
			atomic64_sub(args->in.alloc.mem_size,
					&hdev->dram_used_mem);

			dev_dbg(hdev->dev, "DRAM alloc is not supported\n");
			rc = 0;

			goto out;
		}

		rc = free_device_memory(ctx, &args->in);
		break;

	case HL_MEM_OP_MAP:
		rc = map_device_va(ctx, &args->in, &device_addr);

		memset(args, 0, sizeof(*args));
		args->out.device_virt_addr = device_addr;
		break;

	case HL_MEM_OP_UNMAP:
		rc = unmap_device_va(ctx, &args->in, false);
		break;

	case HL_MEM_OP_MAP_BLOCK:
		rc = map_block(hdev, args->in.map_block.block_addr,
				&block_handle, &block_size);
		args->out.block_handle = block_handle;
		args->out.block_size = block_size;
		break;

	case HL_MEM_OP_EXPORT_DMABUF_FD:
		rc = export_dmabuf_from_addr(ctx,
				args->in.export_dmabuf_fd.addr,
				args->in.export_dmabuf_fd.mem_size,
				args->in.export_dmabuf_fd.offset,
				args->in.flags,
				&dmabuf_fd);
		memset(args, 0, sizeof(*args));
		args->out.fd = dmabuf_fd;
		break;

	case HL_MEM_OP_TS_ALLOC:
		rc = allocate_timestamps_buffers(hpriv, &args->in, &args->out.handle);
		break;
	default:
		dev_err(hdev->dev, "Unknown opcode for memory IOCTL\n");
		rc = -EINVAL;
		break;
	}

out:
	return rc;
}

static int get_user_memory(struct hl_device *hdev, u64 addr, u64 size,
				u32 npages, u64 start, u32 offset,
				struct hl_userptr *userptr)
{
	int rc;

	if (!access_ok((void __user *) (uintptr_t) addr, size)) {
		dev_err(hdev->dev, "user pointer is invalid - 0x%llx\n", addr);
		return -EFAULT;
	}

	userptr->pages = kvmalloc_array(npages, sizeof(struct page *), GFP_KERNEL);
	if (!userptr->pages)
		return -ENOMEM;

	rc = pin_user_pages_fast(start, npages, FOLL_WRITE | FOLL_LONGTERM,
				 userptr->pages);

	if (rc != npages) {
		dev_err(hdev->dev,
			"Failed (%d) to pin host memory with user ptr 0x%llx, size 0x%llx, npages %d\n",
			rc, addr, size, npages);
		if (rc < 0)
			goto destroy_pages;
		npages = rc;
		rc = -EFAULT;
		goto put_pages;
	}
	userptr->npages = npages;

	rc = sg_alloc_table_from_pages(userptr->sgt,
				       userptr->pages,
				       npages, offset, size, GFP_KERNEL);
	if (rc < 0) {
		dev_err(hdev->dev, "failed to create SG table from pages\n");
		goto put_pages;
	}

	return 0;

put_pages:
	unpin_user_pages(userptr->pages, npages);
destroy_pages:
	kvfree(userptr->pages);
	return rc;
}

/**
 * hl_pin_host_memory() - pins a chunk of host memory.
 * @hdev: pointer to the habanalabs device structure.
 * @addr: the host virtual address of the memory area.
 * @size: the size of the memory area.
 * @userptr: pointer to hl_userptr structure.
 *
 * This function does the following:
 * - Pins the physical pages.
 * - Create an SG list from those pages.
 */
int hl_pin_host_memory(struct hl_device *hdev, u64 addr, u64 size,
					struct hl_userptr *userptr)
{
	u64 start, end;
	u32 npages, offset;
	int rc;

	if (!size) {
		dev_err(hdev->dev, "size to pin is invalid - %llu\n", size);
		return -EINVAL;
	}

	/*
	 * If the combination of the address and size requested for this memory
	 * region causes an integer overflow, return error.
	 */
	if (((addr + size) < addr) ||
			PAGE_ALIGN(addr + size) < (addr + size)) {
		dev_err(hdev->dev,
			"user pointer 0x%llx + %llu causes integer overflow\n",
			addr, size);
		return -EINVAL;
	}

	userptr->pid = current->pid;
	userptr->sgt = kzalloc(sizeof(*userptr->sgt), GFP_KERNEL);
	if (!userptr->sgt)
		return -ENOMEM;

	start = addr & PAGE_MASK;
	offset = addr & ~PAGE_MASK;
	end = PAGE_ALIGN(addr + size);
	npages = (end - start) >> PAGE_SHIFT;

	userptr->size = size;
	userptr->addr = addr;
	userptr->dma_mapped = false;
	INIT_LIST_HEAD(&userptr->job_node);

	rc = get_user_memory(hdev, addr, size, npages, start, offset,
				userptr);
	if (rc) {
		dev_err(hdev->dev,
			"failed to get user memory for address 0x%llx\n",
			addr);
		goto free_sgt;
	}

	hl_debugfs_add_userptr(hdev, userptr);

	return 0;

free_sgt:
	kfree(userptr->sgt);
	return rc;
}

/*
 * hl_unpin_host_memory - unpins a chunk of host memory.
 * @hdev: pointer to the habanalabs device structure
 * @userptr: pointer to hl_userptr structure
 *
 * This function does the following:
 * - Unpins the physical pages related to the host memory
 * - Free the SG list
 */
void hl_unpin_host_memory(struct hl_device *hdev, struct hl_userptr *userptr)
{
	hl_debugfs_remove_userptr(hdev, userptr);

	if (userptr->dma_mapped)
		hl_dma_unmap_sgtable(hdev, userptr->sgt, userptr->dir);

	unpin_user_pages_dirty_lock(userptr->pages, userptr->npages, true);
	kvfree(userptr->pages);

	list_del(&userptr->job_node);

	sg_free_table(userptr->sgt);
	kfree(userptr->sgt);
}

/**
 * hl_userptr_delete_list() - clear userptr list.
 * @hdev: pointer to the habanalabs device structure.
 * @userptr_list: pointer to the list to clear.
 *
 * This function does the following:
 * - Iterates over the list and unpins the host memory and frees the userptr
 *   structure.
 */
void hl_userptr_delete_list(struct hl_device *hdev,
				struct list_head *userptr_list)
{
	struct hl_userptr *userptr, *tmp;

	list_for_each_entry_safe(userptr, tmp, userptr_list, job_node) {
		hl_unpin_host_memory(hdev, userptr);
		kfree(userptr);
	}

	INIT_LIST_HEAD(userptr_list);
}

/**
 * hl_userptr_is_pinned() - returns whether the given userptr is pinned.
 * @hdev: pointer to the habanalabs device structure.
 * @addr: user address to check.
 * @size: user block size to check.
 * @userptr_list: pointer to the list to clear.
 * @userptr: pointer to userptr to check.
 *
 * This function does the following:
 * - Iterates over the list and checks if the given userptr is in it, means is
 *   pinned. If so, returns true, otherwise returns false.
 */
bool hl_userptr_is_pinned(struct hl_device *hdev, u64 addr,
				u32 size, struct list_head *userptr_list,
				struct hl_userptr **userptr)
{
	list_for_each_entry((*userptr), userptr_list, job_node) {
		if ((addr == (*userptr)->addr) && (size == (*userptr)->size))
			return true;
	}

	return false;
}

/**
 * va_range_init() - initialize virtual addresses range.
 * @hdev: pointer to the habanalabs device structure.
 * @va_ranges: pointer to va_ranges array.
 * @range_type: virtual address range type.
 * @start: range start address, inclusive.
 * @end: range end address, inclusive.
 * @page_size: page size for this va_range.
 *
 * This function does the following:
 * - Initializes the virtual addresses list of the given range with the given
 *   addresses.
 */
static int va_range_init(struct hl_device *hdev, struct hl_va_range **va_ranges,
				enum hl_va_range_type range_type, u64 start,
				u64 end, u32 page_size)
{
	struct hl_va_range *va_range = va_ranges[range_type];
	int rc;

	INIT_LIST_HEAD(&va_range->list);

	/*
	 * PAGE_SIZE alignment
	 * it is the caller's responsibility to align the addresses if the
	 * page size is not a power of 2
	 */

	if (is_power_of_2(page_size)) {
		start = round_up(start, page_size);

		/*
		 * The end of the range is inclusive, hence we need to align it
		 * to the end of the last full page in the range. For example if
		 * end = 0x3ff5 with page size 0x1000, we need to align it to
		 * 0x2fff. The remaining 0xff5 bytes do not form a full page.
		 */
		end = round_down(end + 1, page_size) - 1;
	}

	if (start >= end) {
		dev_err(hdev->dev, "too small vm range for va list\n");
		return -EFAULT;
	}

	rc = add_va_block(hdev, va_range, start, end);

	if (rc) {
		dev_err(hdev->dev, "Failed to init host va list\n");
		return rc;
	}

	va_range->start_addr = start;
	va_range->end_addr = end;
	va_range->page_size = page_size;

	return 0;
}

/**
 * va_range_fini() - clear a virtual addresses range.
 * @hdev: pointer to the habanalabs structure.
 * @va_range: pointer to virtual addresses range.
 *
 * This function does the following:
 * - Frees the virtual addresses block list and its lock.
 */
static void va_range_fini(struct hl_device *hdev, struct hl_va_range *va_range)
{
	mutex_lock(&va_range->lock);
	clear_va_list_locked(hdev, &va_range->list);
	mutex_unlock(&va_range->lock);

	mutex_destroy(&va_range->lock);
	kfree(va_range);
}

/**
 * vm_ctx_init_with_ranges() - initialize virtual memory for context.
 * @ctx: pointer to the habanalabs context structure.
 * @host_range_start: host virtual addresses range start.
 * @host_range_end: host virtual addresses range end.
 * @host_page_size: host page size.
 * @host_huge_range_start: host virtual addresses range start for memory
 *                         allocated with huge pages.
 * @host_huge_range_end: host virtual addresses range end for memory allocated
 *                        with huge pages.
 * @host_huge_page_size: host huge page size.
 * @dram_range_start: dram virtual addresses range start.
 * @dram_range_end: dram virtual addresses range end.
 * @dram_page_size: dram page size.
 *
 * This function initializes the following:
 * - MMU for context.
 * - Virtual address to area descriptor hashtable.
 * - Virtual block list of available virtual memory.
 */
static int vm_ctx_init_with_ranges(struct hl_ctx *ctx,
					u64 host_range_start,
					u64 host_range_end,
					u32 host_page_size,
					u64 host_huge_range_start,
					u64 host_huge_range_end,
					u32 host_huge_page_size,
					u64 dram_range_start,
					u64 dram_range_end,
					u32 dram_page_size)
{
	struct hl_device *hdev = ctx->hdev;
	int i, rc;

	for (i = 0 ; i < HL_VA_RANGE_TYPE_MAX ; i++) {
		ctx->va_range[i] =
			kzalloc(sizeof(struct hl_va_range), GFP_KERNEL);
		if (!ctx->va_range[i]) {
			rc = -ENOMEM;
			goto free_va_range;
		}
	}

	rc = hl_mmu_ctx_init(ctx);
	if (rc) {
		dev_err(hdev->dev, "failed to init context %d\n", ctx->asid);
		goto free_va_range;
	}

	mutex_init(&ctx->mem_hash_lock);
	hash_init(ctx->mem_hash);

	mutex_init(&ctx->va_range[HL_VA_RANGE_TYPE_HOST]->lock);

	rc = va_range_init(hdev, ctx->va_range, HL_VA_RANGE_TYPE_HOST,
			host_range_start, host_range_end, host_page_size);
	if (rc) {
		dev_err(hdev->dev, "failed to init host vm range\n");
		goto mmu_ctx_fini;
	}

	if (hdev->pmmu_huge_range) {
		mutex_init(&ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE]->lock);

		rc = va_range_init(hdev,
			ctx->va_range, HL_VA_RANGE_TYPE_HOST_HUGE,
			host_huge_range_start, host_huge_range_end,
			host_huge_page_size);
		if (rc) {
			dev_err(hdev->dev,
				"failed to init host huge vm range\n");
			goto clear_host_va_range;
		}
	} else {
		kfree(ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE]);
		ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE] =
				ctx->va_range[HL_VA_RANGE_TYPE_HOST];
	}

	mutex_init(&ctx->va_range[HL_VA_RANGE_TYPE_DRAM]->lock);

	rc = va_range_init(hdev, ctx->va_range, HL_VA_RANGE_TYPE_DRAM,
			dram_range_start, dram_range_end, dram_page_size);
	if (rc) {
		dev_err(hdev->dev, "failed to init dram vm range\n");
		goto clear_host_huge_va_range;
	}

	hl_debugfs_add_ctx_mem_hash(hdev, ctx);

	return 0;

clear_host_huge_va_range:
	mutex_destroy(&ctx->va_range[HL_VA_RANGE_TYPE_DRAM]->lock);

	if (hdev->pmmu_huge_range) {
		mutex_lock(&ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE]->lock);
		clear_va_list_locked(hdev,
			&ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE]->list);
		mutex_unlock(&ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE]->lock);
	}
clear_host_va_range:
	if (hdev->pmmu_huge_range)
		mutex_destroy(&ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE]->lock);
	mutex_lock(&ctx->va_range[HL_VA_RANGE_TYPE_HOST]->lock);
	clear_va_list_locked(hdev, &ctx->va_range[HL_VA_RANGE_TYPE_HOST]->list);
	mutex_unlock(&ctx->va_range[HL_VA_RANGE_TYPE_HOST]->lock);
mmu_ctx_fini:
	mutex_destroy(&ctx->va_range[HL_VA_RANGE_TYPE_HOST]->lock);
	mutex_destroy(&ctx->mem_hash_lock);
	hl_mmu_ctx_fini(ctx);
free_va_range:
	for (i = 0 ; i < HL_VA_RANGE_TYPE_MAX ; i++)
		kfree(ctx->va_range[i]);

	return rc;
}

int hl_vm_ctx_init(struct hl_ctx *ctx)
{
	struct asic_fixed_properties *prop = &ctx->hdev->asic_prop;
	u64 host_range_start, host_range_end, host_huge_range_start,
		host_huge_range_end, dram_range_start, dram_range_end;
	u32 host_page_size, host_huge_page_size, dram_page_size;

	atomic64_set(&ctx->dram_phys_mem, 0);

	/*
	 *   In case of DRAM mapping, the returned address is the physical
	 *   address of the memory related to the given handle.
	 */
	if (ctx->hdev->mmu_disable)
		return 0;

	dram_range_start = prop->dmmu.start_addr;
	dram_range_end = prop->dmmu.end_addr - 1;
	dram_page_size = prop->dram_page_size ?
				prop->dram_page_size : prop->dmmu.page_size;
	host_range_start = prop->pmmu.start_addr;
	host_range_end = prop->pmmu.end_addr - 1;
	host_page_size = prop->pmmu.page_size;
	host_huge_range_start = prop->pmmu_huge.start_addr;
	host_huge_range_end = prop->pmmu_huge.end_addr - 1;
	host_huge_page_size = prop->pmmu_huge.page_size;

	return vm_ctx_init_with_ranges(ctx, host_range_start, host_range_end,
			host_page_size, host_huge_range_start,
			host_huge_range_end, host_huge_page_size,
			dram_range_start, dram_range_end, dram_page_size);
}

/**
 * hl_vm_ctx_fini() - virtual memory teardown of context.
 * @ctx: pointer to the habanalabs context structure.
 *
 * This function perform teardown the following:
 * - Virtual block list of available virtual memory.
 * - Virtual address to area descriptor hashtable.
 * - MMU for context.
 *
 * In addition this function does the following:
 * - Unmaps the existing hashtable nodes if the hashtable is not empty. The
 *   hashtable should be empty as no valid mappings should exist at this
 *   point.
 * - Frees any existing physical page list from the idr which relates to the
 *   current context asid.
 * - This function checks the virtual block list for correctness. At this point
 *   the list should contain one element which describes the whole virtual
 *   memory range of the context. Otherwise, a warning is printed.
 */
void hl_vm_ctx_fini(struct hl_ctx *ctx)
{
	struct hl_vm_phys_pg_pack *phys_pg_list, *tmp_phys_node;
	struct hl_device *hdev = ctx->hdev;
	struct hl_vm_hash_node *hnode;
	struct hl_vm *vm = &hdev->vm;
	struct hlist_node *tmp_node;
	struct list_head free_list;
	struct hl_mem_in args;
	int i;

	if (hdev->mmu_disable)
		return;

	hl_debugfs_remove_ctx_mem_hash(hdev, ctx);

	/*
	 * Clearly something went wrong on hard reset so no point in printing
	 * another side effect error
	 */
	if (!hdev->reset_info.hard_reset_pending && !hash_empty(ctx->mem_hash))
		dev_dbg(hdev->dev,
			"user released device without removing its memory mappings\n");

	hash_for_each_safe(ctx->mem_hash, i, tmp_node, hnode, node) {
		dev_dbg(hdev->dev,
			"hl_mem_hash_node of vaddr 0x%llx of asid %d is still alive\n",
			hnode->vaddr, ctx->asid);
		args.unmap.device_virt_addr = hnode->vaddr;
		unmap_device_va(ctx, &args, true);
	}

	mutex_lock(&hdev->mmu_lock);

	/* invalidate the cache once after the unmapping loop */
	hl_mmu_invalidate_cache(hdev, true, MMU_OP_USERPTR);
	hl_mmu_invalidate_cache(hdev, true, MMU_OP_PHYS_PACK);

	mutex_unlock(&hdev->mmu_lock);

	INIT_LIST_HEAD(&free_list);

	spin_lock(&vm->idr_lock);
	idr_for_each_entry(&vm->phys_pg_pack_handles, phys_pg_list, i)
		if (phys_pg_list->asid == ctx->asid) {
			dev_dbg(hdev->dev,
				"page list 0x%px of asid %d is still alive\n",
				phys_pg_list, ctx->asid);

			atomic64_sub(phys_pg_list->total_size, &hdev->dram_used_mem);
			idr_remove(&vm->phys_pg_pack_handles, i);
			list_add(&phys_pg_list->node, &free_list);
		}
	spin_unlock(&vm->idr_lock);

	list_for_each_entry_safe(phys_pg_list, tmp_phys_node, &free_list, node)
		free_phys_pg_pack(hdev, phys_pg_list);

	va_range_fini(hdev, ctx->va_range[HL_VA_RANGE_TYPE_DRAM]);
	va_range_fini(hdev, ctx->va_range[HL_VA_RANGE_TYPE_HOST]);

	if (hdev->pmmu_huge_range)
		va_range_fini(hdev, ctx->va_range[HL_VA_RANGE_TYPE_HOST_HUGE]);

	mutex_destroy(&ctx->mem_hash_lock);
	hl_mmu_ctx_fini(ctx);

	/* In this case we need to clear the global accounting of DRAM usage
	 * because the user notifies us on allocations. If the user is no more,
	 * all DRAM is available
	 */
	if (ctx->asid != HL_KERNEL_ASID_ID &&
			!hdev->asic_prop.dram_supports_virtual_memory)
		atomic64_set(&hdev->dram_used_mem, 0);
}

/**
 * hl_vm_init() - initialize virtual memory module.
 * @hdev: pointer to the habanalabs device structure.
 *
 * This function initializes the following:
 * - MMU module.
 * - DRAM physical pages pool of 2MB.
 * - Idr for device memory allocation handles.
 */
int hl_vm_init(struct hl_device *hdev)
{
	struct asic_fixed_properties *prop = &hdev->asic_prop;
	struct hl_vm *vm = &hdev->vm;
	int rc;

	if (is_power_of_2(prop->dram_page_size))
		vm->dram_pg_pool =
			gen_pool_create(__ffs(prop->dram_page_size), -1);
	else
		vm->dram_pg_pool =
			gen_pool_create(__ffs(DRAM_POOL_PAGE_SIZE), -1);

	if (!vm->dram_pg_pool) {
		dev_err(hdev->dev, "Failed to create dram page pool\n");
		return -ENOMEM;
	}

	kref_init(&vm->dram_pg_pool_refcount);

	rc = gen_pool_add(vm->dram_pg_pool, prop->dram_user_base_address,
			prop->dram_end_address - prop->dram_user_base_address,
			-1);

	if (rc) {
		dev_err(hdev->dev,
			"Failed to add memory to dram page pool %d\n", rc);
		goto pool_add_err;
	}

	spin_lock_init(&vm->idr_lock);
	idr_init(&vm->phys_pg_pack_handles);

	atomic64_set(&hdev->dram_used_mem, 0);

	vm->init_done = true;

	return 0;

pool_add_err:
	gen_pool_destroy(vm->dram_pg_pool);

	return rc;
}

/**
 * hl_vm_fini() - virtual memory module teardown.
 * @hdev: pointer to the habanalabs device structure.
 *
 * This function perform teardown to the following:
 * - Idr for device memory allocation handles.
 * - DRAM physical pages pool of 2MB.
 * - MMU module.
 */
void hl_vm_fini(struct hl_device *hdev)
{
	struct hl_vm *vm = &hdev->vm;

	if (!vm->init_done)
		return;

	/*
	 * At this point all the contexts should be freed and hence no DRAM
	 * memory should be in use. Hence the DRAM pool should be freed here.
	 */
	if (kref_put(&vm->dram_pg_pool_refcount, dram_pg_pool_do_release) != 1)
		dev_warn(hdev->dev, "dram_pg_pool was not destroyed on %s\n",
				__func__);

	vm->init_done = false;
}

/**
 * hl_hw_block_mem_init() - HW block memory initialization.
 * @ctx: pointer to the habanalabs context structure.
 *
 * This function initializes the HW block virtual mapped addresses list and
 * it's lock.
 */
void hl_hw_block_mem_init(struct hl_ctx *ctx)
{
	mutex_init(&ctx->hw_block_list_lock);
	INIT_LIST_HEAD(&ctx->hw_block_mem_list);
}

/**
 * hl_hw_block_mem_fini() - HW block memory teardown.
 * @ctx: pointer to the habanalabs context structure.
 *
 * This function clears the HW block virtual mapped addresses list and destroys
 * it's lock.
 */
void hl_hw_block_mem_fini(struct hl_ctx *ctx)
{
	struct hl_vm_hw_block_list_node *lnode, *tmp;

	if (!list_empty(&ctx->hw_block_mem_list))
		dev_crit(ctx->hdev->dev, "HW block mem list isn't empty\n");

	list_for_each_entry_safe(lnode, tmp, &ctx->hw_block_mem_list, node) {
		list_del(&lnode->node);
		kfree(lnode);
	}

	mutex_destroy(&ctx->hw_block_list_lock);
}
