/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2019 Intel Corporation. All rights rsvd. */
#ifndef _IDXD_H_
#define _IDXD_H_

#include <linux/sbitmap.h>
#include <linux/dmaengine.h>
#include <linux/percpu-rwsem.h>
#include <linux/wait.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/pci.h>
#include <linux/bitmap.h>
#include <linux/perf_event.h>
#include <linux/iommu.h>
#include <linux/crypto.h>
#include <uapi/linux/idxd.h>
#include "registers.h"

#define IDXD_DRIVER_VERSION	"1.00"

extern bool tc_override;

struct idxd_wq;
struct idxd_dev;

enum idxd_dev_type {
	IDXD_DEV_NONE = -1,
	IDXD_DEV_DSA = 0,
	IDXD_DEV_IAX,
	IDXD_DEV_WQ,
	IDXD_DEV_GROUP,
	IDXD_DEV_ENGINE,
	IDXD_DEV_CDEV,
	IDXD_DEV_CDEV_FILE,
	IDXD_DEV_MAX_TYPE,
};

struct idxd_dev {
	struct device conf_dev;
	enum idxd_dev_type type;
};

#define IDXD_REG_TIMEOUT	50
#define IDXD_DRAIN_TIMEOUT	5000

enum idxd_type {
	IDXD_TYPE_UNKNOWN = -1,
	IDXD_TYPE_DSA = 0,
	IDXD_TYPE_IAX,
	IDXD_TYPE_MAX,
};

#define IDXD_NAME_SIZE		128
#define IDXD_PMU_EVENT_MAX	64

#define IDXD_ENQCMDS_RETRIES		32
#define IDXD_ENQCMDS_MAX_RETRIES	64

enum idxd_complete_type {
	IDXD_COMPLETE_NORMAL = 0,
	IDXD_COMPLETE_ABORT,
	IDXD_COMPLETE_DEV_FAIL,
};

struct idxd_desc;

struct idxd_device_driver {
	const char *name;
	enum idxd_dev_type *type;
	int (*probe)(struct idxd_dev *idxd_dev);
	void (*remove)(struct idxd_dev *idxd_dev);
	void (*desc_complete)(struct idxd_desc *desc,
			      enum idxd_complete_type comp_type,
			      bool free_desc,
			      void *ctx, u32 *status);
	struct device_driver drv;
};

extern struct idxd_device_driver dsa_drv;
extern struct idxd_device_driver idxd_drv;
extern struct idxd_device_driver idxd_dmaengine_drv;
extern struct idxd_device_driver idxd_user_drv;

#define INVALID_INT_HANDLE	-1
struct idxd_irq_entry {
	int id;
	int vector;
	struct llist_head pending_llist;
	struct list_head work_list;
	/*
	 * Lock to protect access between irq thread process descriptor
	 * and irq thread processing error descriptor.
	 */
	spinlock_t list_lock;
	int int_handle;
	ioasid_t pasid;
};

struct idxd_group {
	struct idxd_dev idxd_dev;
	struct idxd_device *idxd;
	struct grpcfg grpcfg;
	int id;
	int num_engines;
	int num_wqs;
	bool use_rdbuf_limit;
	u8 rdbufs_allowed;
	u8 rdbufs_reserved;
	int tc_a;
	int tc_b;
	int desc_progress_limit;
	int batch_progress_limit;
};

struct idxd_pmu {
	struct idxd_device *idxd;

	struct perf_event *event_list[IDXD_PMU_EVENT_MAX];
	int n_events;

	DECLARE_BITMAP(used_mask, IDXD_PMU_EVENT_MAX);

	struct pmu pmu;
	char name[IDXD_NAME_SIZE];

	int n_counters;
	int counter_width;
	int n_event_categories;

	bool per_counter_caps_supported;
	unsigned long supported_event_categories;

	unsigned long supported_filters;
	int n_filters;
};

#define IDXD_MAX_PRIORITY	0xf

enum {
	COUNTER_FAULTS = 0,
	COUNTER_FAULT_FAILS,
	COUNTER_MAX
};

enum idxd_wq_state {
	IDXD_WQ_DISABLED = 0,
	IDXD_WQ_ENABLED,
};

enum idxd_wq_flag {
	WQ_FLAG_DEDICATED = 0,
	WQ_FLAG_BLOCK_ON_FAULT,
	WQ_FLAG_ATS_DISABLE,
	WQ_FLAG_PRS_DISABLE,
};

enum idxd_wq_type {
	IDXD_WQT_NONE = 0,
	IDXD_WQT_KERNEL,
	IDXD_WQT_USER,
};

struct idxd_cdev {
	struct idxd_wq *wq;
	struct cdev cdev;
	struct idxd_dev idxd_dev;
	int minor;
};

#define DRIVER_NAME_SIZE		128

#define WQ_NAME_SIZE   1024
#define WQ_TYPE_SIZE   10

#define WQ_DEFAULT_QUEUE_DEPTH		16
#define WQ_DEFAULT_MAX_XFER		SZ_2M
#define WQ_DEFAULT_MAX_BATCH		32

enum idxd_op_type {
	IDXD_OP_BLOCK = 0,
	IDXD_OP_NONBLOCK = 1,
};

struct idxd_dma_chan {
	struct dma_chan chan;
	struct idxd_wq *wq;
};

struct idxd_wq {
	void __iomem *portal;
	u32 portal_offset;
	unsigned int enqcmds_retries;
	struct percpu_ref wq_active;
	struct completion wq_dead;
	struct completion wq_resurrect;
	struct idxd_dev idxd_dev;
	struct idxd_cdev *idxd_cdev;
	struct wait_queue_head err_queue;
	struct workqueue_struct *wq;
	struct idxd_device *idxd;
	int id;
	struct idxd_irq_entry ie;
	enum idxd_wq_type type;
	struct idxd_group *group;
	int client_count;
	struct mutex wq_lock;	/* mutex for workqueue */
	u32 size;
	u32 threshold;
	u32 priority;
	enum idxd_wq_state state;
	unsigned long flags;
	union wqcfg *wqcfg;
	unsigned long *opcap_bmap;

	struct dsa_hw_desc **hw_descs;
	int num_descs;
	union {
		struct dsa_completion_record *compls;
		struct iax_completion_record *iax_compls;
	};
	dma_addr_t compls_addr;
	int compls_size;
	struct idxd_desc **descs;
	struct sbitmap_queue sbq;
	struct idxd_dma_chan *idxd_chan;
	char name[WQ_NAME_SIZE + 1];
	u64 max_xfer_bytes;
	u32 max_batch_size;

	/* Lock to protect upasid_xa access. */
	struct mutex uc_lock;
	struct xarray upasid_xa;

	char driver_name[DRIVER_NAME_SIZE + 1];
};

struct idxd_engine {
	struct idxd_dev idxd_dev;
	int id;
	struct idxd_group *group;
	struct idxd_device *idxd;
};

/* shadow registers */
struct idxd_hw {
	u32 version;
	union gen_cap_reg gen_cap;
	union wq_cap_reg wq_cap;
	union group_cap_reg group_cap;
	union engine_cap_reg engine_cap;
	struct opcap opcap;
	u32 cmd_cap;
	union iaa_cap_reg iaa_cap;
};

enum idxd_device_state {
	IDXD_DEV_HALTED = -1,
	IDXD_DEV_DISABLED = 0,
	IDXD_DEV_ENABLED,
};

enum idxd_device_flag {
	IDXD_FLAG_CONFIGURABLE = 0,
	IDXD_FLAG_CMD_RUNNING,
	IDXD_FLAG_PASID_ENABLED,
	IDXD_FLAG_USER_PASID_ENABLED,
};

struct idxd_dma_dev {
	struct idxd_device *idxd;
	struct dma_device dma;
};

typedef int (*load_device_defaults_fn_t) (struct idxd_device *idxd);

struct idxd_driver_data {
	const char *name_prefix;
	enum idxd_type type;
	const struct device_type *dev_type;
	int compl_size;
	int align;
	int evl_cr_off;
	int cr_status_off;
	int cr_result_off;
	bool user_submission_safe;
	load_device_defaults_fn_t load_device_defaults;
};

struct idxd_evl {
	/* Lock to protect event log access. */
	struct mutex lock;
	void *log;
	dma_addr_t dma;
	/* Total size of event log = number of entries * entry size. */
	unsigned int log_size;
	/* The number of entries in the event log. */
	u16 size;
	unsigned long *bmap;
	bool batch_fail[IDXD_MAX_BATCH_IDENT];
};

struct idxd_evl_fault {
	struct work_struct work;
	struct idxd_wq *wq;
	u8 status;

	/* make this last member always */
	struct __evl_entry entry[];
};

struct idxd_device {
	struct idxd_dev idxd_dev;
	struct idxd_driver_data *data;
	struct list_head list;
	struct idxd_hw hw;
	enum idxd_device_state state;
	unsigned long flags;
	int id;
	int major;
	u32 cmd_status;
	struct idxd_irq_entry ie;	/* misc irq, msix 0 */

	struct pci_dev *pdev;
	void __iomem *reg_base;

	spinlock_t dev_lock;	/* spinlock for device */
	spinlock_t cmd_lock;	/* spinlock for device commands */
	struct completion *cmd_done;
	struct idxd_group **groups;
	struct idxd_wq **wqs;
	struct idxd_engine **engines;

	struct iommu_sva *sva;
	unsigned int pasid;

	int num_groups;
	int irq_cnt;
	bool request_int_handles;

	u32 msix_perm_offset;
	u32 wqcfg_offset;
	u32 grpcfg_offset;
	u32 perfmon_offset;

	u64 max_xfer_bytes;
	u32 max_batch_size;
	int max_groups;
	int max_engines;
	int max_rdbufs;
	int max_wqs;
	int max_wq_size;
	int rdbuf_limit;
	int nr_rdbufs;		/* non-reserved read buffers */
	unsigned int wqcfg_size;
	unsigned long *wq_enable_map;

	union sw_err_reg sw_err;
	wait_queue_head_t cmd_waitq;

	struct idxd_dma_dev *idxd_dma;
	struct workqueue_struct *wq;
	struct work_struct work;

	struct idxd_pmu *idxd_pmu;

	unsigned long *opcap_bmap;
	struct idxd_evl *evl;
	struct kmem_cache *evl_cache;

	struct dentry *dbgfs_dir;
	struct dentry *dbgfs_evl_file;

	bool user_submission_safe;

	struct idxd_saved_states *idxd_saved;
};

struct idxd_saved_states {
	struct idxd_device saved_idxd;
	struct idxd_evl saved_evl;
	struct idxd_engine **saved_engines;
	struct idxd_wq **saved_wqs;
	struct idxd_group **saved_groups;
	unsigned long *saved_wq_enable_map;
};

static inline unsigned int evl_ent_size(struct idxd_device *idxd)
{
	return idxd->hw.gen_cap.evl_support ?
	       (32 * (1 << idxd->hw.gen_cap.evl_support)) : 0;
}

static inline unsigned int evl_size(struct idxd_device *idxd)
{
	return idxd->evl->size * evl_ent_size(idxd);
}

struct crypto_ctx {
	struct acomp_req *req;
	struct crypto_tfm *tfm;
	dma_addr_t src_addr;
	dma_addr_t dst_addr;
	bool compress;
};

/* IDXD software descriptor */
struct idxd_desc {
	union {
		struct dsa_hw_desc *hw;
		struct iax_hw_desc *iax_hw;
	};
	dma_addr_t desc_dma;
	union {
		struct dsa_completion_record *completion;
		struct iax_completion_record *iax_completion;
	};
	dma_addr_t compl_dma;
	union {
		struct dma_async_tx_descriptor txd;
		struct crypto_ctx crypto;
	};
	struct llist_node llnode;
	struct list_head list;
	int id;
	int cpu;
	struct idxd_wq *wq;
};

/*
 * This is software defined error for the completion status. We overload the error code
 * that will never appear in completion status and only SWERR register.
 */
enum idxd_completion_status {
	IDXD_COMP_DESC_ABORT = 0xff,
};

#define idxd_confdev(idxd) &idxd->idxd_dev.conf_dev
#define wq_confdev(wq) &wq->idxd_dev.conf_dev
#define engine_confdev(engine) &engine->idxd_dev.conf_dev
#define group_confdev(group) &group->idxd_dev.conf_dev
#define cdev_dev(cdev) &cdev->idxd_dev.conf_dev
#define user_ctx_dev(ctx) (&(ctx)->idxd_dev.conf_dev)

#define confdev_to_idxd_dev(dev) container_of(dev, struct idxd_dev, conf_dev)
#define idxd_dev_to_idxd(idxd_dev) container_of(idxd_dev, struct idxd_device, idxd_dev)
#define idxd_dev_to_wq(idxd_dev) container_of(idxd_dev, struct idxd_wq, idxd_dev)

static inline struct idxd_device_driver *wq_to_idxd_drv(struct idxd_wq *wq)
{
	struct device *dev = wq_confdev(wq);
	struct idxd_device_driver *idxd_drv =
		container_of(dev->driver, struct idxd_device_driver, drv);

	return idxd_drv;
}

static inline struct idxd_device *confdev_to_idxd(struct device *dev)
{
	struct idxd_dev *idxd_dev = confdev_to_idxd_dev(dev);

	return idxd_dev_to_idxd(idxd_dev);
}

static inline struct idxd_wq *confdev_to_wq(struct device *dev)
{
	struct idxd_dev *idxd_dev = confdev_to_idxd_dev(dev);

	return idxd_dev_to_wq(idxd_dev);
}

static inline struct idxd_engine *confdev_to_engine(struct device *dev)
{
	struct idxd_dev *idxd_dev = confdev_to_idxd_dev(dev);

	return container_of(idxd_dev, struct idxd_engine, idxd_dev);
}

static inline struct idxd_group *confdev_to_group(struct device *dev)
{
	struct idxd_dev *idxd_dev = confdev_to_idxd_dev(dev);

	return container_of(idxd_dev, struct idxd_group, idxd_dev);
}

static inline struct idxd_cdev *dev_to_cdev(struct device *dev)
{
	struct idxd_dev *idxd_dev = confdev_to_idxd_dev(dev);

	return container_of(idxd_dev, struct idxd_cdev, idxd_dev);
}

static inline void idxd_dev_set_type(struct idxd_dev *idev, int type)
{
	if (type >= IDXD_DEV_MAX_TYPE) {
		idev->type = IDXD_DEV_NONE;
		return;
	}

	idev->type = type;
}

static inline struct idxd_irq_entry *idxd_get_ie(struct idxd_device *idxd, int idx)
{
	return (idx == 0) ? &idxd->ie : &idxd->wqs[idx - 1]->ie;
}

static inline struct idxd_wq *ie_to_wq(struct idxd_irq_entry *ie)
{
	return container_of(ie, struct idxd_wq, ie);
}

static inline struct idxd_device *ie_to_idxd(struct idxd_irq_entry *ie)
{
	return container_of(ie, struct idxd_device, ie);
}

static inline void idxd_set_user_intr(struct idxd_device *idxd, bool enable)
{
	union gencfg_reg reg;

	reg.bits = ioread32(idxd->reg_base + IDXD_GENCFG_OFFSET);
	reg.user_int_en = enable;
	iowrite32(reg.bits, idxd->reg_base + IDXD_GENCFG_OFFSET);
}

extern const struct bus_type dsa_bus_type;

extern bool support_enqcmd;
extern struct ida idxd_ida;
extern const struct device_type dsa_device_type;
extern const struct device_type iax_device_type;
extern const struct device_type idxd_wq_device_type;
extern const struct device_type idxd_engine_device_type;
extern const struct device_type idxd_group_device_type;

static inline bool is_dsa_dev(struct idxd_dev *idxd_dev)
{
	return idxd_dev->type == IDXD_DEV_DSA;
}

static inline bool is_iax_dev(struct idxd_dev *idxd_dev)
{
	return idxd_dev->type == IDXD_DEV_IAX;
}

static inline bool is_idxd_dev(struct idxd_dev *idxd_dev)
{
	return is_dsa_dev(idxd_dev) || is_iax_dev(idxd_dev);
}

static inline bool is_idxd_wq_dev(struct idxd_dev *idxd_dev)
{
	return idxd_dev->type == IDXD_DEV_WQ;
}

static inline bool is_idxd_wq_dmaengine(struct idxd_wq *wq)
{
	if (wq->type == IDXD_WQT_KERNEL && strcmp(wq->name, "dmaengine") == 0)
		return true;
	return false;
}

static inline bool is_idxd_wq_user(struct idxd_wq *wq)
{
	return wq->type == IDXD_WQT_USER;
}

static inline bool is_idxd_wq_kernel(struct idxd_wq *wq)
{
	return wq->type == IDXD_WQT_KERNEL;
}

static inline bool wq_dedicated(struct idxd_wq *wq)
{
	return test_bit(WQ_FLAG_DEDICATED, &wq->flags);
}

static inline bool wq_shared(struct idxd_wq *wq)
{
	return !test_bit(WQ_FLAG_DEDICATED, &wq->flags);
}

static inline bool device_pasid_enabled(struct idxd_device *idxd)
{
	return test_bit(IDXD_FLAG_PASID_ENABLED, &idxd->flags);
}

static inline bool device_user_pasid_enabled(struct idxd_device *idxd)
{
	return test_bit(IDXD_FLAG_USER_PASID_ENABLED, &idxd->flags);
}

static inline bool wq_pasid_enabled(struct idxd_wq *wq)
{
	return (is_idxd_wq_kernel(wq) && device_pasid_enabled(wq->idxd)) ||
	       (is_idxd_wq_user(wq) && device_user_pasid_enabled(wq->idxd));
}

static inline bool wq_shared_supported(struct idxd_wq *wq)
{
	return (support_enqcmd && wq_pasid_enabled(wq));
}

enum idxd_portal_prot {
	IDXD_PORTAL_UNLIMITED = 0,
	IDXD_PORTAL_LIMITED,
};

enum idxd_interrupt_type {
	IDXD_IRQ_MSIX = 0,
	IDXD_IRQ_IMS,
};

static inline int idxd_get_wq_portal_offset(enum idxd_portal_prot prot)
{
	return prot * 0x1000;
}

static inline int idxd_get_wq_portal_full_offset(int wq_id,
						 enum idxd_portal_prot prot)
{
	return ((wq_id * 4) << PAGE_SHIFT) + idxd_get_wq_portal_offset(prot);
}

#define IDXD_PORTAL_MASK	(PAGE_SIZE - 1)

/*
 * Even though this function can be accessed by multiple threads, it is safe to use.
 * At worst the address gets used more than once before it gets incremented. We don't
 * hit a threshold until iops becomes many million times a second. So the occasional
 * reuse of the same address is tolerable compare to using an atomic variable. This is
 * safe on a system that has atomic load/store for 32bit integers. Given that this is an
 * Intel iEP device, that should not be a problem.
 */
static inline void __iomem *idxd_wq_portal_addr(struct idxd_wq *wq)
{
	int ofs = wq->portal_offset;

	wq->portal_offset = (ofs + sizeof(struct dsa_raw_desc)) & IDXD_PORTAL_MASK;
	return wq->portal + ofs;
}

static inline void idxd_wq_get(struct idxd_wq *wq)
{
	wq->client_count++;
}

static inline void idxd_wq_put(struct idxd_wq *wq)
{
	wq->client_count--;
}

static inline int idxd_wq_refcount(struct idxd_wq *wq)
{
	return wq->client_count;
};

static inline void idxd_wq_set_private(struct idxd_wq *wq, void *private)
{
	dev_set_drvdata(wq_confdev(wq), private);
}

static inline void *idxd_wq_get_private(struct idxd_wq *wq)
{
	return dev_get_drvdata(wq_confdev(wq));
}

/*
 * Intel IAA does not support batch processing.
 * The max batch size of device, max batch size of wq and
 * max batch shift of wqcfg should be always 0 on IAA.
 */
static inline void idxd_set_max_batch_size(int idxd_type, struct idxd_device *idxd,
					   u32 max_batch_size)
{
	if (idxd_type == IDXD_TYPE_IAX)
		idxd->max_batch_size = 0;
	else
		idxd->max_batch_size = max_batch_size;
}

static inline void idxd_wq_set_max_batch_size(int idxd_type, struct idxd_wq *wq,
					      u32 max_batch_size)
{
	if (idxd_type == IDXD_TYPE_IAX)
		wq->max_batch_size = 0;
	else
		wq->max_batch_size = max_batch_size;
}

static inline void idxd_wqcfg_set_max_batch_shift(int idxd_type, union wqcfg *wqcfg,
						  u32 max_batch_shift)
{
	if (idxd_type == IDXD_TYPE_IAX)
		wqcfg->max_batch_shift = 0;
	else
		wqcfg->max_batch_shift = max_batch_shift;
}

static inline int idxd_wq_driver_name_match(struct idxd_wq *wq, struct device *dev)
{
	return (strncmp(wq->driver_name, dev->driver->name, strlen(dev->driver->name)) == 0);
}

#define MODULE_ALIAS_IDXD_DEVICE(type) MODULE_ALIAS("idxd:t" __stringify(type) "*")
#define IDXD_DEVICES_MODALIAS_FMT "idxd:t%d"

int __must_check __idxd_driver_register(struct idxd_device_driver *idxd_drv,
					struct module *module, const char *mod_name);
#define idxd_driver_register(driver) \
	__idxd_driver_register(driver, THIS_MODULE, KBUILD_MODNAME)

void idxd_driver_unregister(struct idxd_device_driver *idxd_drv);

#define module_idxd_driver(__idxd_driver) \
	module_driver(__idxd_driver, idxd_driver_register, idxd_driver_unregister)

void idxd_free_desc(struct idxd_wq *wq, struct idxd_desc *desc);
void idxd_dma_complete_txd(struct idxd_desc *desc,
			   enum idxd_complete_type comp_type,
			   bool free_desc, void *ctx, u32 *status);

static inline void idxd_desc_complete(struct idxd_desc *desc,
				      enum idxd_complete_type comp_type,
				      bool free_desc)
{
	struct idxd_device_driver *drv;
	u32 status;

	drv = wq_to_idxd_drv(desc->wq);
	if (drv->desc_complete)
		drv->desc_complete(desc, comp_type, free_desc,
				   &desc->txd, &status);
}

int idxd_register_devices(struct idxd_device *idxd);
void idxd_unregister_devices(struct idxd_device *idxd);
void idxd_wqs_quiesce(struct idxd_device *idxd);
bool idxd_queue_int_handle_resubmit(struct idxd_desc *desc);
void multi_u64_to_bmap(unsigned long *bmap, u64 *val, int count);
int idxd_load_iaa_device_defaults(struct idxd_device *idxd);

/* device interrupt control */
irqreturn_t idxd_misc_thread(int vec, void *data);
irqreturn_t idxd_wq_thread(int irq, void *data);
void idxd_mask_error_interrupts(struct idxd_device *idxd);
void idxd_unmask_error_interrupts(struct idxd_device *idxd);

/* device control */
int idxd_device_drv_probe(struct idxd_dev *idxd_dev);
int idxd_pci_probe_alloc(struct idxd_device *idxd, struct pci_dev *pdev,
			 const struct pci_device_id *id);
void idxd_device_drv_remove(struct idxd_dev *idxd_dev);
int idxd_drv_enable_wq(struct idxd_wq *wq);
void idxd_drv_disable_wq(struct idxd_wq *wq);
int idxd_device_init_reset(struct idxd_device *idxd);
int idxd_device_enable(struct idxd_device *idxd);
int idxd_device_disable(struct idxd_device *idxd);
void idxd_device_reset(struct idxd_device *idxd);
void idxd_device_clear_state(struct idxd_device *idxd);
int idxd_device_config(struct idxd_device *idxd);
void idxd_device_drain_pasid(struct idxd_device *idxd, int pasid);
int idxd_device_load_config(struct idxd_device *idxd);
int idxd_device_request_int_handle(struct idxd_device *idxd, int idx, int *handle,
				   enum idxd_interrupt_type irq_type);
int idxd_device_release_int_handle(struct idxd_device *idxd, int handle,
				   enum idxd_interrupt_type irq_type);

/* work queue control */
void idxd_wqs_unmap_portal(struct idxd_device *idxd);
int idxd_wq_alloc_resources(struct idxd_wq *wq);
void idxd_wq_free_resources(struct idxd_wq *wq);
int idxd_wq_enable(struct idxd_wq *wq);
int idxd_wq_disable(struct idxd_wq *wq, bool reset_config);
void idxd_wq_drain(struct idxd_wq *wq);
void idxd_wq_reset(struct idxd_wq *wq);
int idxd_wq_map_portal(struct idxd_wq *wq);
void idxd_wq_unmap_portal(struct idxd_wq *wq);
int idxd_wq_set_pasid(struct idxd_wq *wq, int pasid);
int idxd_wq_disable_pasid(struct idxd_wq *wq);
void __idxd_wq_quiesce(struct idxd_wq *wq);
void idxd_wq_quiesce(struct idxd_wq *wq);
int idxd_wq_init_percpu_ref(struct idxd_wq *wq);
void idxd_wq_free_irq(struct idxd_wq *wq);
int idxd_wq_request_irq(struct idxd_wq *wq);

/* submission */
int idxd_submit_desc(struct idxd_wq *wq, struct idxd_desc *desc);
struct idxd_desc *idxd_alloc_desc(struct idxd_wq *wq, enum idxd_op_type optype);
int idxd_enqcmds(struct idxd_wq *wq, void __iomem *portal, const void *desc);

/* dmaengine */
int idxd_register_dma_device(struct idxd_device *idxd);
void idxd_unregister_dma_device(struct idxd_device *idxd);

/* cdev */
int idxd_cdev_register(void);
void idxd_cdev_remove(void);
int idxd_cdev_get_major(struct idxd_device *idxd);
int idxd_wq_add_cdev(struct idxd_wq *wq);
void idxd_wq_del_cdev(struct idxd_wq *wq);
int idxd_copy_cr(struct idxd_wq *wq, ioasid_t pasid, unsigned long addr,
		 void *buf, int len);
void idxd_user_counter_increment(struct idxd_wq *wq, u32 pasid, int index);

/* perfmon */
#if IS_ENABLED(CONFIG_INTEL_IDXD_PERFMON)
int perfmon_pmu_init(struct idxd_device *idxd);
void perfmon_pmu_remove(struct idxd_device *idxd);
void perfmon_counter_overflow(struct idxd_device *idxd);
#else
static inline int perfmon_pmu_init(struct idxd_device *idxd) { return 0; }
static inline void perfmon_pmu_remove(struct idxd_device *idxd) {}
static inline void perfmon_counter_overflow(struct idxd_device *idxd) {}
#endif

/* debugfs */
int idxd_device_init_debugfs(struct idxd_device *idxd);
void idxd_device_remove_debugfs(struct idxd_device *idxd);
int idxd_init_debugfs(void);
void idxd_remove_debugfs(void);

#endif
