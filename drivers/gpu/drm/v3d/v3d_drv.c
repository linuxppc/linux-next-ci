// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2014-2018 Broadcom */

/**
 * DOC: Broadcom V3D Graphics Driver
 *
 * This driver supports the Broadcom V3D 3.3 and 4.1 OpenGL ES GPUs.
 * For V3D 2.x support, see the VC4 driver.
 *
 * The V3D GPU includes a tiled render (composed of a bin and render
 * pipelines), the TFU (texture formatting unit), and the CSD (compute
 * shader dispatch).
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/sched/clock.h>
#include <linux/reset.h>

#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <uapi/drm/v3d_drm.h>

#include "v3d_drv.h"
#include "v3d_regs.h"

#define DRIVER_NAME "v3d"
#define DRIVER_DESC "Broadcom V3D graphics"
#define DRIVER_MAJOR 1
#define DRIVER_MINOR 0
#define DRIVER_PATCHLEVEL 0

/* Only expose the `super_pages` modparam if THP is enabled. */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
bool super_pages = true;
module_param_named(super_pages, super_pages, bool, 0400);
MODULE_PARM_DESC(super_pages, "Enable/Disable Super Pages support.");
#endif

static int v3d_get_param_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file_priv)
{
	struct v3d_file_priv *v3d_priv = file_priv->driver_priv;
	struct v3d_dev *v3d = to_v3d_dev(dev);
	struct drm_v3d_get_param *args = data;
	static const u32 reg_map[] = {
		[DRM_V3D_PARAM_V3D_UIFCFG] = V3D_HUB_UIFCFG,
		[DRM_V3D_PARAM_V3D_HUB_IDENT1] = V3D_HUB_IDENT1,
		[DRM_V3D_PARAM_V3D_HUB_IDENT2] = V3D_HUB_IDENT2,
		[DRM_V3D_PARAM_V3D_HUB_IDENT3] = V3D_HUB_IDENT3,
		[DRM_V3D_PARAM_V3D_CORE0_IDENT0] = V3D_CTL_IDENT0,
		[DRM_V3D_PARAM_V3D_CORE0_IDENT1] = V3D_CTL_IDENT1,
		[DRM_V3D_PARAM_V3D_CORE0_IDENT2] = V3D_CTL_IDENT2,
	};

	if (args->pad != 0)
		return -EINVAL;

	/* Note that DRM_V3D_PARAM_V3D_CORE0_IDENT0 is 0, so we need
	 * to explicitly allow it in the "the register in our
	 * parameter map" check.
	 */
	if (args->param < ARRAY_SIZE(reg_map) &&
	    (reg_map[args->param] ||
	     args->param == DRM_V3D_PARAM_V3D_CORE0_IDENT0)) {
		u32 offset = reg_map[args->param];

		if (args->value != 0)
			return -EINVAL;

		if (args->param >= DRM_V3D_PARAM_V3D_CORE0_IDENT0 &&
		    args->param <= DRM_V3D_PARAM_V3D_CORE0_IDENT2) {
			args->value = V3D_CORE_READ(0, offset);
		} else {
			args->value = V3D_READ(offset);
		}
		return 0;
	}

	switch (args->param) {
	case DRM_V3D_PARAM_SUPPORTS_TFU:
		args->value = 1;
		return 0;
	case DRM_V3D_PARAM_SUPPORTS_CSD:
		args->value = v3d_has_csd(v3d);
		return 0;
	case DRM_V3D_PARAM_SUPPORTS_CACHE_FLUSH:
		args->value = 1;
		return 0;
	case DRM_V3D_PARAM_SUPPORTS_PERFMON:
		args->value = (v3d->ver >= V3D_GEN_41);
		return 0;
	case DRM_V3D_PARAM_SUPPORTS_MULTISYNC_EXT:
		args->value = 1;
		return 0;
	case DRM_V3D_PARAM_SUPPORTS_CPU_QUEUE:
		args->value = 1;
		return 0;
	case DRM_V3D_PARAM_MAX_PERF_COUNTERS:
		args->value = v3d->perfmon_info.max_counters;
		return 0;
	case DRM_V3D_PARAM_SUPPORTS_SUPER_PAGES:
		args->value = !!v3d->gemfs;
		return 0;
	case DRM_V3D_PARAM_GLOBAL_RESET_COUNTER:
		mutex_lock(&v3d->reset_lock);
		args->value = v3d->reset_counter;
		mutex_unlock(&v3d->reset_lock);
		return 0;
	case DRM_V3D_PARAM_CONTEXT_RESET_COUNTER:
		mutex_lock(&v3d->reset_lock);
		args->value = v3d_priv->reset_counter;
		mutex_unlock(&v3d->reset_lock);
		return 0;
	default:
		DRM_DEBUG("Unknown parameter %d\n", args->param);
		return -EINVAL;
	}
}

static int
v3d_open(struct drm_device *dev, struct drm_file *file)
{
	struct v3d_dev *v3d = to_v3d_dev(dev);
	struct v3d_file_priv *v3d_priv;
	struct drm_gpu_scheduler *sched;
	int i;

	v3d_priv = kzalloc(sizeof(*v3d_priv), GFP_KERNEL);
	if (!v3d_priv)
		return -ENOMEM;

	v3d_priv->v3d = v3d;

	for (i = 0; i < V3D_MAX_QUEUES; i++) {
		sched = &v3d->queue[i].sched;
		drm_sched_entity_init(&v3d_priv->sched_entity[i],
				      DRM_SCHED_PRIORITY_NORMAL, &sched,
				      1, NULL);

		memset(&v3d_priv->stats[i], 0, sizeof(v3d_priv->stats[i]));
		seqcount_init(&v3d_priv->stats[i].lock);
	}

	v3d_perfmon_open_file(v3d_priv);
	file->driver_priv = v3d_priv;

	return 0;
}

static void
v3d_postclose(struct drm_device *dev, struct drm_file *file)
{
	struct v3d_file_priv *v3d_priv = file->driver_priv;
	enum v3d_queue q;

	for (q = 0; q < V3D_MAX_QUEUES; q++)
		drm_sched_entity_destroy(&v3d_priv->sched_entity[q]);

	v3d_perfmon_close_file(v3d_priv);
	kfree(v3d_priv);
}

void v3d_get_stats(const struct v3d_stats *stats, u64 timestamp,
		   u64 *active_runtime, u64 *jobs_completed)
{
	unsigned int seq;

	do {
		seq = read_seqcount_begin(&stats->lock);
		*active_runtime = stats->enabled_ns;
		if (stats->start_ns)
			*active_runtime += timestamp - stats->start_ns;
		*jobs_completed = stats->jobs_completed;
	} while (read_seqcount_retry(&stats->lock, seq));
}

static void v3d_show_fdinfo(struct drm_printer *p, struct drm_file *file)
{
	struct v3d_file_priv *file_priv = file->driver_priv;
	u64 timestamp = local_clock();
	enum v3d_queue queue;

	for (queue = 0; queue < V3D_MAX_QUEUES; queue++) {
		struct v3d_stats *stats = &file_priv->stats[queue];
		u64 active_runtime, jobs_completed;

		v3d_get_stats(stats, timestamp, &active_runtime, &jobs_completed);

		/* Note that, in case of a GPU reset, the time spent during an
		 * attempt of executing the job is not computed in the runtime.
		 */
		drm_printf(p, "drm-engine-%s: \t%llu ns\n",
			   v3d_queue_to_string(queue), active_runtime);

		/* Note that we only count jobs that completed. Therefore, jobs
		 * that were resubmitted due to a GPU reset are not computed.
		 */
		drm_printf(p, "v3d-jobs-%s: \t%llu jobs\n",
			   v3d_queue_to_string(queue), jobs_completed);
	}

	drm_show_memory_stats(p, file);
}

static const struct file_operations v3d_drm_fops = {
	.owner = THIS_MODULE,
	DRM_GEM_FOPS,
	.show_fdinfo = drm_show_fdinfo,
};

/* DRM_AUTH is required on SUBMIT_CL for now, while we don't have GMP
 * protection between clients.  Note that render nodes would be
 * able to submit CLs that could access BOs from clients authenticated
 * with the master node.  The TFU doesn't use the GMP, so it would
 * need to stay DRM_AUTH until we do buffer size/offset validation.
 */
static const struct drm_ioctl_desc v3d_drm_ioctls[] = {
	DRM_IOCTL_DEF_DRV(V3D_SUBMIT_CL, v3d_submit_cl_ioctl, DRM_RENDER_ALLOW | DRM_AUTH),
	DRM_IOCTL_DEF_DRV(V3D_WAIT_BO, v3d_wait_bo_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_CREATE_BO, v3d_create_bo_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_MMAP_BO, v3d_mmap_bo_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_GET_PARAM, v3d_get_param_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_GET_BO_OFFSET, v3d_get_bo_offset_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_SUBMIT_TFU, v3d_submit_tfu_ioctl, DRM_RENDER_ALLOW | DRM_AUTH),
	DRM_IOCTL_DEF_DRV(V3D_SUBMIT_CSD, v3d_submit_csd_ioctl, DRM_RENDER_ALLOW | DRM_AUTH),
	DRM_IOCTL_DEF_DRV(V3D_PERFMON_CREATE, v3d_perfmon_create_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_PERFMON_DESTROY, v3d_perfmon_destroy_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_PERFMON_GET_VALUES, v3d_perfmon_get_values_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_SUBMIT_CPU, v3d_submit_cpu_ioctl, DRM_RENDER_ALLOW | DRM_AUTH),
	DRM_IOCTL_DEF_DRV(V3D_PERFMON_GET_COUNTER, v3d_perfmon_get_counter_ioctl, DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(V3D_PERFMON_SET_GLOBAL, v3d_perfmon_set_global_ioctl, DRM_RENDER_ALLOW),
};

static const struct drm_driver v3d_drm_driver = {
	.driver_features = (DRIVER_GEM |
			    DRIVER_RENDER |
			    DRIVER_SYNCOBJ),

	.open = v3d_open,
	.postclose = v3d_postclose,

#if defined(CONFIG_DEBUG_FS)
	.debugfs_init = v3d_debugfs_init,
#endif

	.gem_create_object = v3d_create_object,
	.gem_prime_import_sg_table = v3d_prime_import_sg_table,

	.ioctls = v3d_drm_ioctls,
	.num_ioctls = ARRAY_SIZE(v3d_drm_ioctls),
	.fops = &v3d_drm_fops,
	.show_fdinfo = v3d_show_fdinfo,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static const struct of_device_id v3d_of_match[] = {
	{ .compatible = "brcm,2711-v3d", .data = (void *)V3D_GEN_42 },
	{ .compatible = "brcm,2712-v3d", .data = (void *)V3D_GEN_71 },
	{ .compatible = "brcm,7268-v3d", .data = (void *)V3D_GEN_33 },
	{ .compatible = "brcm,7278-v3d", .data = (void *)V3D_GEN_41 },
	{},
};
MODULE_DEVICE_TABLE(of, v3d_of_match);

static void
v3d_idle_sms(struct v3d_dev *v3d)
{
	if (v3d->ver < V3D_GEN_71)
		return;

	V3D_SMS_WRITE(V3D_SMS_TEE_CS, V3D_SMS_CLEAR_POWER_OFF);

	if (wait_for((V3D_GET_FIELD(V3D_SMS_READ(V3D_SMS_TEE_CS),
				    V3D_SMS_STATE) == V3D_SMS_IDLE), 100)) {
		DRM_ERROR("Failed to power up SMS\n");
	}

	v3d_reset_sms(v3d);
}

static void
v3d_power_off_sms(struct v3d_dev *v3d)
{
	if (v3d->ver < V3D_GEN_71)
		return;

	V3D_SMS_WRITE(V3D_SMS_TEE_CS, V3D_SMS_POWER_OFF);

	if (wait_for((V3D_GET_FIELD(V3D_SMS_READ(V3D_SMS_TEE_CS),
				    V3D_SMS_STATE) == V3D_SMS_POWER_OFF_STATE), 100)) {
		DRM_ERROR("Failed to power off SMS\n");
	}
}

static int
map_regs(struct v3d_dev *v3d, void __iomem **regs, const char *name)
{
	*regs = devm_platform_ioremap_resource_byname(v3d_to_pdev(v3d), name);
	return PTR_ERR_OR_ZERO(*regs);
}

static int v3d_platform_drm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct drm_device *drm;
	struct v3d_dev *v3d;
	enum v3d_gen gen;
	int ret;
	u32 mmu_debug;
	u32 ident1, ident3;
	u64 mask;

	v3d = devm_drm_dev_alloc(dev, &v3d_drm_driver, struct v3d_dev, drm);
	if (IS_ERR(v3d))
		return PTR_ERR(v3d);

	drm = &v3d->drm;

	platform_set_drvdata(pdev, drm);

	gen = (uintptr_t)of_device_get_match_data(dev);
	v3d->ver = gen;

	ret = map_regs(v3d, &v3d->hub_regs, "hub");
	if (ret)
		return ret;

	ret = map_regs(v3d, &v3d->core_regs[0], "core0");
	if (ret)
		return ret;

	if (v3d->ver >= V3D_GEN_71) {
		ret = map_regs(v3d, &v3d->sms_regs, "sms");
		if (ret)
			return ret;
	}

	v3d->clk = devm_clk_get_optional(dev, NULL);
	if (IS_ERR(v3d->clk))
		return dev_err_probe(dev, PTR_ERR(v3d->clk), "Failed to get V3D clock\n");

	ret = clk_prepare_enable(v3d->clk);
	if (ret) {
		dev_err(&pdev->dev, "Couldn't enable the V3D clock\n");
		return ret;
	}

	v3d_idle_sms(v3d);

	mmu_debug = V3D_READ(V3D_MMU_DEBUG_INFO);
	mask = DMA_BIT_MASK(30 + V3D_GET_FIELD(mmu_debug, V3D_MMU_PA_WIDTH));
	ret = dma_set_mask_and_coherent(dev, mask);
	if (ret)
		goto clk_disable;

	v3d->va_width = 30 + V3D_GET_FIELD(mmu_debug, V3D_MMU_VA_WIDTH);

	ident1 = V3D_READ(V3D_HUB_IDENT1);
	v3d->ver = (V3D_GET_FIELD(ident1, V3D_HUB_IDENT1_TVER) * 10 +
		    V3D_GET_FIELD(ident1, V3D_HUB_IDENT1_REV));
	/* Make sure that the V3D tech version retrieved from the HW is equal
	 * to the one advertised by the device tree.
	 */
	WARN_ON(v3d->ver != gen);

	v3d->cores = V3D_GET_FIELD(ident1, V3D_HUB_IDENT1_NCORES);
	WARN_ON(v3d->cores > 1); /* multicore not yet implemented */

	ident3 = V3D_READ(V3D_HUB_IDENT3);
	v3d->rev = V3D_GET_FIELD(ident3, V3D_HUB_IDENT3_IPREV);

	v3d_perfmon_init(v3d);

	v3d->reset = devm_reset_control_get_exclusive(dev, NULL);
	if (IS_ERR(v3d->reset)) {
		ret = PTR_ERR(v3d->reset);

		if (ret == -EPROBE_DEFER)
			goto clk_disable;

		v3d->reset = NULL;
		ret = map_regs(v3d, &v3d->bridge_regs, "bridge");
		if (ret) {
			dev_err(dev,
				"Failed to get reset control or bridge regs\n");
			goto clk_disable;
		}
	}

	if (v3d->ver < V3D_GEN_41) {
		ret = map_regs(v3d, &v3d->gca_regs, "gca");
		if (ret)
			goto clk_disable;
	}

	v3d->mmu_scratch = dma_alloc_wc(dev, 4096, &v3d->mmu_scratch_paddr,
					GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
	if (!v3d->mmu_scratch) {
		dev_err(dev, "Failed to allocate MMU scratch page\n");
		ret = -ENOMEM;
		goto clk_disable;
	}

	ret = v3d_gem_init(drm);
	if (ret)
		goto dma_free;

	ret = v3d_irq_init(v3d);
	if (ret)
		goto gem_destroy;

	ret = drm_dev_register(drm, 0);
	if (ret)
		goto irq_disable;

	ret = v3d_sysfs_init(dev);
	if (ret)
		goto drm_unregister;

	return 0;

drm_unregister:
	drm_dev_unregister(drm);
irq_disable:
	v3d_irq_disable(v3d);
gem_destroy:
	v3d_gem_destroy(drm);
dma_free:
	dma_free_wc(dev, 4096, v3d->mmu_scratch, v3d->mmu_scratch_paddr);
clk_disable:
	clk_disable_unprepare(v3d->clk);
	return ret;
}

static void v3d_platform_drm_remove(struct platform_device *pdev)
{
	struct drm_device *drm = platform_get_drvdata(pdev);
	struct v3d_dev *v3d = to_v3d_dev(drm);
	struct device *dev = &pdev->dev;

	v3d_sysfs_destroy(dev);

	drm_dev_unregister(drm);

	v3d_gem_destroy(drm);

	dma_free_wc(v3d->drm.dev, 4096, v3d->mmu_scratch,
		    v3d->mmu_scratch_paddr);

	v3d_power_off_sms(v3d);

	clk_disable_unprepare(v3d->clk);
}

static struct platform_driver v3d_platform_driver = {
	.probe		= v3d_platform_drm_probe,
	.remove		= v3d_platform_drm_remove,
	.driver		= {
		.name	= "v3d",
		.of_match_table = v3d_of_match,
	},
};

module_platform_driver(v3d_platform_driver);

MODULE_ALIAS("platform:v3d-drm");
MODULE_DESCRIPTION("Broadcom V3D DRM Driver");
MODULE_AUTHOR("Eric Anholt <eric@anholt.net>");
MODULE_LICENSE("GPL v2");
