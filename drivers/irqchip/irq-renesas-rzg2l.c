// SPDX-License-Identifier: GPL-2.0
/*
 * Renesas RZ/G2L IRQC Driver
 *
 * Copyright (C) 2022 Renesas Electronics Corporation.
 *
 * Author: Lad Prabhakar <prabhakar.mahadev-lad.rj@bp.renesas.com>
 */

#include <linux/bitfield.h>
#include <linux/cleanup.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <linux/spinlock.h>
#include <linux/syscore_ops.h>

#define IRQC_IRQ_START			1
#define IRQC_IRQ_COUNT			8
#define IRQC_TINT_START			(IRQC_IRQ_START + IRQC_IRQ_COUNT)
#define IRQC_TINT_COUNT			32
#define IRQC_NUM_IRQ			(IRQC_TINT_START + IRQC_TINT_COUNT)

#define ISCR				0x10
#define IITSR				0x14
#define TSCR				0x20
#define TITSR(n)			(0x24 + (n) * 4)
#define TITSR0_MAX_INT			16
#define TITSEL_WIDTH			0x2
#define TSSR(n)				(0x30 + ((n) * 4))
#define TIEN				BIT(7)
#define TSSEL_SHIFT(n)			(8 * (n))
#define TSSEL_MASK			GENMASK(7, 0)
#define IRQ_MASK			0x3
#define IMSK				0x10010
#define TMSK				0x10020

#define TSSR_OFFSET(n)			((n) % 4)
#define TSSR_INDEX(n)			((n) / 4)

#define TITSR_TITSEL_EDGE_RISING	0
#define TITSR_TITSEL_EDGE_FALLING	1
#define TITSR_TITSEL_LEVEL_HIGH		2
#define TITSR_TITSEL_LEVEL_LOW		3

#define IITSR_IITSEL(n, sense)		((sense) << ((n) * 2))
#define IITSR_IITSEL_LEVEL_LOW		0
#define IITSR_IITSEL_EDGE_FALLING	1
#define IITSR_IITSEL_EDGE_RISING	2
#define IITSR_IITSEL_EDGE_BOTH		3
#define IITSR_IITSEL_MASK(n)		IITSR_IITSEL((n), 3)

#define TINT_EXTRACT_HWIRQ(x)		FIELD_GET(GENMASK(15, 0), (x))
#define TINT_EXTRACT_GPIOINT(x)		FIELD_GET(GENMASK(31, 16), (x))

/**
 * struct rzg2l_irqc_reg_cache - registers cache (necessary for suspend/resume)
 * @iitsr: IITSR register
 * @titsr: TITSR registers
 */
struct rzg2l_irqc_reg_cache {
	u32	iitsr;
	u32	titsr[2];
};

/**
 * struct rzg2l_irqc_priv - IRQ controller private data structure
 * @base:	Controller's base address
 * @irqchip:	Pointer to struct irq_chip
 * @fwspec:	IRQ firmware specific data
 * @lock:	Lock to serialize access to hardware registers
 * @cache:	Registers cache for suspend/resume
 */
static struct rzg2l_irqc_priv {
	void __iomem			*base;
	const struct irq_chip		*irqchip;
	struct irq_fwspec		fwspec[IRQC_NUM_IRQ];
	raw_spinlock_t			lock;
	struct rzg2l_irqc_reg_cache	cache;
} *rzg2l_irqc_data;

static struct rzg2l_irqc_priv *irq_data_to_priv(struct irq_data *data)
{
	return data->domain->host_data;
}

static void rzg2l_clear_irq_int(struct rzg2l_irqc_priv *priv, unsigned int hwirq)
{
	unsigned int hw_irq = hwirq - IRQC_IRQ_START;
	u32 bit = BIT(hw_irq);
	u32 iitsr, iscr;

	iscr = readl_relaxed(priv->base + ISCR);
	iitsr = readl_relaxed(priv->base + IITSR);

	/*
	 * ISCR can only be cleared if the type is falling-edge, rising-edge or
	 * falling/rising-edge.
	 */
	if ((iscr & bit) && (iitsr & IITSR_IITSEL_MASK(hw_irq))) {
		writel_relaxed(iscr & ~bit, priv->base + ISCR);
		/*
		 * Enforce that the posted write is flushed to prevent that the
		 * just handled interrupt is raised again.
		 */
		readl_relaxed(priv->base + ISCR);
	}
}

static void rzg2l_clear_tint_int(struct rzg2l_irqc_priv *priv, unsigned int hwirq)
{
	u32 bit = BIT(hwirq - IRQC_TINT_START);
	u32 reg;

	reg = readl_relaxed(priv->base + TSCR);
	if (reg & bit) {
		writel_relaxed(reg & ~bit, priv->base + TSCR);
		/*
		 * Enforce that the posted write is flushed to prevent that the
		 * just handled interrupt is raised again.
		 */
		readl_relaxed(priv->base + TSCR);
	}
}

static void rzg2l_irqc_eoi(struct irq_data *d)
{
	struct rzg2l_irqc_priv *priv = irq_data_to_priv(d);
	unsigned int hw_irq = irqd_to_hwirq(d);

	raw_spin_lock(&priv->lock);
	if (hw_irq >= IRQC_IRQ_START && hw_irq <= IRQC_IRQ_COUNT)
		rzg2l_clear_irq_int(priv, hw_irq);
	else if (hw_irq >= IRQC_TINT_START && hw_irq < IRQC_NUM_IRQ)
		rzg2l_clear_tint_int(priv, hw_irq);
	raw_spin_unlock(&priv->lock);
	irq_chip_eoi_parent(d);
}

static void rzfive_irqc_mask_irq_interrupt(struct rzg2l_irqc_priv *priv,
					   unsigned int hwirq)
{
	u32 bit = BIT(hwirq - IRQC_IRQ_START);

	writel_relaxed(readl_relaxed(priv->base + IMSK) | bit, priv->base + IMSK);
}

static void rzfive_irqc_unmask_irq_interrupt(struct rzg2l_irqc_priv *priv,
					     unsigned int hwirq)
{
	u32 bit = BIT(hwirq - IRQC_IRQ_START);

	writel_relaxed(readl_relaxed(priv->base + IMSK) & ~bit, priv->base + IMSK);
}

static void rzfive_irqc_mask_tint_interrupt(struct rzg2l_irqc_priv *priv,
					    unsigned int hwirq)
{
	u32 bit = BIT(hwirq - IRQC_TINT_START);

	writel_relaxed(readl_relaxed(priv->base + TMSK) | bit, priv->base + TMSK);
}

static void rzfive_irqc_unmask_tint_interrupt(struct rzg2l_irqc_priv *priv,
					      unsigned int hwirq)
{
	u32 bit = BIT(hwirq - IRQC_TINT_START);

	writel_relaxed(readl_relaxed(priv->base + TMSK) & ~bit, priv->base + TMSK);
}

static void rzfive_irqc_mask(struct irq_data *d)
{
	struct rzg2l_irqc_priv *priv = irq_data_to_priv(d);
	unsigned int hwirq = irqd_to_hwirq(d);

	raw_spin_lock(&priv->lock);
	if (hwirq >= IRQC_IRQ_START && hwirq <= IRQC_IRQ_COUNT)
		rzfive_irqc_mask_irq_interrupt(priv, hwirq);
	else if (hwirq >= IRQC_TINT_START && hwirq < IRQC_NUM_IRQ)
		rzfive_irqc_mask_tint_interrupt(priv, hwirq);
	raw_spin_unlock(&priv->lock);
	irq_chip_mask_parent(d);
}

static void rzfive_irqc_unmask(struct irq_data *d)
{
	struct rzg2l_irqc_priv *priv = irq_data_to_priv(d);
	unsigned int hwirq = irqd_to_hwirq(d);

	raw_spin_lock(&priv->lock);
	if (hwirq >= IRQC_IRQ_START && hwirq <= IRQC_IRQ_COUNT)
		rzfive_irqc_unmask_irq_interrupt(priv, hwirq);
	else if (hwirq >= IRQC_TINT_START && hwirq < IRQC_NUM_IRQ)
		rzfive_irqc_unmask_tint_interrupt(priv, hwirq);
	raw_spin_unlock(&priv->lock);
	irq_chip_unmask_parent(d);
}

static void rzfive_tint_irq_endisable(struct irq_data *d, bool enable)
{
	struct rzg2l_irqc_priv *priv = irq_data_to_priv(d);
	unsigned int hwirq = irqd_to_hwirq(d);

	if (hwirq >= IRQC_TINT_START && hwirq < IRQC_NUM_IRQ) {
		u32 offset = hwirq - IRQC_TINT_START;
		u32 tssr_offset = TSSR_OFFSET(offset);
		u8 tssr_index = TSSR_INDEX(offset);
		u32 reg;

		raw_spin_lock(&priv->lock);
		if (enable)
			rzfive_irqc_unmask_tint_interrupt(priv, hwirq);
		else
			rzfive_irqc_mask_tint_interrupt(priv, hwirq);
		reg = readl_relaxed(priv->base + TSSR(tssr_index));
		if (enable)
			reg |= TIEN << TSSEL_SHIFT(tssr_offset);
		else
			reg &= ~(TIEN << TSSEL_SHIFT(tssr_offset));
		writel_relaxed(reg, priv->base + TSSR(tssr_index));
		raw_spin_unlock(&priv->lock);
	} else {
		raw_spin_lock(&priv->lock);
		if (enable)
			rzfive_irqc_unmask_irq_interrupt(priv, hwirq);
		else
			rzfive_irqc_mask_irq_interrupt(priv, hwirq);
		raw_spin_unlock(&priv->lock);
	}
}

static void rzfive_irqc_irq_disable(struct irq_data *d)
{
	irq_chip_disable_parent(d);
	rzfive_tint_irq_endisable(d, false);
}

static void rzfive_irqc_irq_enable(struct irq_data *d)
{
	rzfive_tint_irq_endisable(d, true);
	irq_chip_enable_parent(d);
}

static void rzg2l_tint_irq_endisable(struct irq_data *d, bool enable)
{
	unsigned int hw_irq = irqd_to_hwirq(d);

	if (hw_irq >= IRQC_TINT_START && hw_irq < IRQC_NUM_IRQ) {
		struct rzg2l_irqc_priv *priv = irq_data_to_priv(d);
		u32 offset = hw_irq - IRQC_TINT_START;
		u32 tssr_offset = TSSR_OFFSET(offset);
		u8 tssr_index = TSSR_INDEX(offset);
		u32 reg;

		raw_spin_lock(&priv->lock);
		reg = readl_relaxed(priv->base + TSSR(tssr_index));
		if (enable)
			reg |= TIEN << TSSEL_SHIFT(tssr_offset);
		else
			reg &= ~(TIEN << TSSEL_SHIFT(tssr_offset));
		writel_relaxed(reg, priv->base + TSSR(tssr_index));
		raw_spin_unlock(&priv->lock);
	}
}

static void rzg2l_irqc_irq_disable(struct irq_data *d)
{
	irq_chip_disable_parent(d);
	rzg2l_tint_irq_endisable(d, false);
}

static void rzg2l_irqc_irq_enable(struct irq_data *d)
{
	rzg2l_tint_irq_endisable(d, true);
	irq_chip_enable_parent(d);
}

static int rzg2l_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct rzg2l_irqc_priv *priv = irq_data_to_priv(d);
	unsigned int hwirq = irqd_to_hwirq(d);
	u32 iitseln = hwirq - IRQC_IRQ_START;
	bool clear_irq_int = false;
	u16 sense, tmp;

	switch (type & IRQ_TYPE_SENSE_MASK) {
	case IRQ_TYPE_LEVEL_LOW:
		sense = IITSR_IITSEL_LEVEL_LOW;
		break;

	case IRQ_TYPE_EDGE_FALLING:
		sense = IITSR_IITSEL_EDGE_FALLING;
		clear_irq_int = true;
		break;

	case IRQ_TYPE_EDGE_RISING:
		sense = IITSR_IITSEL_EDGE_RISING;
		clear_irq_int = true;
		break;

	case IRQ_TYPE_EDGE_BOTH:
		sense = IITSR_IITSEL_EDGE_BOTH;
		clear_irq_int = true;
		break;

	default:
		return -EINVAL;
	}

	raw_spin_lock(&priv->lock);
	tmp = readl_relaxed(priv->base + IITSR);
	tmp &= ~IITSR_IITSEL_MASK(iitseln);
	tmp |= IITSR_IITSEL(iitseln, sense);
	if (clear_irq_int)
		rzg2l_clear_irq_int(priv, hwirq);
	writel_relaxed(tmp, priv->base + IITSR);
	raw_spin_unlock(&priv->lock);

	return 0;
}

static u32 rzg2l_disable_tint_and_set_tint_source(struct irq_data *d, struct rzg2l_irqc_priv *priv,
						  u32 reg, u32 tssr_offset, u8 tssr_index)
{
	u32 tint = (u32)(uintptr_t)irq_data_get_irq_chip_data(d);
	u32 tien = reg & (TIEN << TSSEL_SHIFT(tssr_offset));

	/* Clear the relevant byte in reg */
	reg &= ~(TSSEL_MASK << TSSEL_SHIFT(tssr_offset));
	/* Set TINT and leave TIEN clear */
	reg |= tint << TSSEL_SHIFT(tssr_offset);
	writel_relaxed(reg, priv->base + TSSR(tssr_index));

	return reg | tien;
}

static int rzg2l_tint_set_edge(struct irq_data *d, unsigned int type)
{
	struct rzg2l_irqc_priv *priv = irq_data_to_priv(d);
	unsigned int hwirq = irqd_to_hwirq(d);
	u32 titseln = hwirq - IRQC_TINT_START;
	u32 tssr_offset = TSSR_OFFSET(titseln);
	u8 tssr_index = TSSR_INDEX(titseln);
	u8 index, sense;
	u32 reg, tssr;

	switch (type & IRQ_TYPE_SENSE_MASK) {
	case IRQ_TYPE_EDGE_RISING:
		sense = TITSR_TITSEL_EDGE_RISING;
		break;

	case IRQ_TYPE_EDGE_FALLING:
		sense = TITSR_TITSEL_EDGE_FALLING;
		break;

	default:
		return -EINVAL;
	}

	index = 0;
	if (titseln >= TITSR0_MAX_INT) {
		titseln -= TITSR0_MAX_INT;
		index = 1;
	}

	raw_spin_lock(&priv->lock);
	tssr = readl_relaxed(priv->base + TSSR(tssr_index));
	tssr = rzg2l_disable_tint_and_set_tint_source(d, priv, tssr, tssr_offset, tssr_index);
	reg = readl_relaxed(priv->base + TITSR(index));
	reg &= ~(IRQ_MASK << (titseln * TITSEL_WIDTH));
	reg |= sense << (titseln * TITSEL_WIDTH);
	writel_relaxed(reg, priv->base + TITSR(index));
	rzg2l_clear_tint_int(priv, hwirq);
	writel_relaxed(tssr, priv->base + TSSR(tssr_index));
	raw_spin_unlock(&priv->lock);

	return 0;
}

static int rzg2l_irqc_set_type(struct irq_data *d, unsigned int type)
{
	unsigned int hw_irq = irqd_to_hwirq(d);
	int ret = -EINVAL;

	if (hw_irq >= IRQC_IRQ_START && hw_irq <= IRQC_IRQ_COUNT)
		ret = rzg2l_irq_set_type(d, type);
	else if (hw_irq >= IRQC_TINT_START && hw_irq < IRQC_NUM_IRQ)
		ret = rzg2l_tint_set_edge(d, type);
	if (ret)
		return ret;

	return irq_chip_set_type_parent(d, IRQ_TYPE_LEVEL_HIGH);
}

static int rzg2l_irqc_irq_suspend(void)
{
	struct rzg2l_irqc_reg_cache *cache = &rzg2l_irqc_data->cache;
	void __iomem *base = rzg2l_irqc_data->base;

	cache->iitsr = readl_relaxed(base + IITSR);
	for (u8 i = 0; i < 2; i++)
		cache->titsr[i] = readl_relaxed(base + TITSR(i));

	return 0;
}

static void rzg2l_irqc_irq_resume(void)
{
	struct rzg2l_irqc_reg_cache *cache = &rzg2l_irqc_data->cache;
	void __iomem *base = rzg2l_irqc_data->base;

	/*
	 * Restore only interrupt type. TSSRx will be restored at the
	 * request of pin controller to avoid spurious interrupts due
	 * to invalid PIN states.
	 */
	for (u8 i = 0; i < 2; i++)
		writel_relaxed(cache->titsr[i], base + TITSR(i));
	writel_relaxed(cache->iitsr, base + IITSR);
}

static struct syscore_ops rzg2l_irqc_syscore_ops = {
	.suspend	= rzg2l_irqc_irq_suspend,
	.resume		= rzg2l_irqc_irq_resume,
};

static const struct irq_chip rzg2l_irqc_chip = {
	.name			= "rzg2l-irqc",
	.irq_eoi		= rzg2l_irqc_eoi,
	.irq_mask		= irq_chip_mask_parent,
	.irq_unmask		= irq_chip_unmask_parent,
	.irq_disable		= rzg2l_irqc_irq_disable,
	.irq_enable		= rzg2l_irqc_irq_enable,
	.irq_get_irqchip_state	= irq_chip_get_parent_state,
	.irq_set_irqchip_state	= irq_chip_set_parent_state,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_set_type		= rzg2l_irqc_set_type,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.flags			= IRQCHIP_MASK_ON_SUSPEND |
				  IRQCHIP_SET_TYPE_MASKED |
				  IRQCHIP_SKIP_SET_WAKE,
};

static const struct irq_chip rzfive_irqc_chip = {
	.name			= "rzfive-irqc",
	.irq_eoi		= rzg2l_irqc_eoi,
	.irq_mask		= rzfive_irqc_mask,
	.irq_unmask		= rzfive_irqc_unmask,
	.irq_disable		= rzfive_irqc_irq_disable,
	.irq_enable		= rzfive_irqc_irq_enable,
	.irq_get_irqchip_state	= irq_chip_get_parent_state,
	.irq_set_irqchip_state	= irq_chip_set_parent_state,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_set_type		= rzg2l_irqc_set_type,
	.irq_set_affinity	= irq_chip_set_affinity_parent,
	.flags			= IRQCHIP_MASK_ON_SUSPEND |
				  IRQCHIP_SET_TYPE_MASKED |
				  IRQCHIP_SKIP_SET_WAKE,
};

static int rzg2l_irqc_alloc(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs, void *arg)
{
	struct rzg2l_irqc_priv *priv = domain->host_data;
	unsigned long tint = 0;
	irq_hw_number_t hwirq;
	unsigned int type;
	int ret;

	ret = irq_domain_translate_twocell(domain, arg, &hwirq, &type);
	if (ret)
		return ret;

	/*
	 * For TINT interrupts ie where pinctrl driver is child of irqc domain
	 * the hwirq and TINT are encoded in fwspec->param[0].
	 * hwirq for TINT range from 9-40, hwirq is embedded 0-15 bits and TINT
	 * from 16-31 bits. TINT from the pinctrl driver needs to be programmed
	 * in IRQC registers to enable a given gpio pin as interrupt.
	 */
	if (hwirq > IRQC_IRQ_COUNT) {
		tint = TINT_EXTRACT_GPIOINT(hwirq);
		hwirq = TINT_EXTRACT_HWIRQ(hwirq);

		if (hwirq < IRQC_TINT_START)
			return -EINVAL;
	}

	if (hwirq > (IRQC_NUM_IRQ - 1))
		return -EINVAL;

	ret = irq_domain_set_hwirq_and_chip(domain, virq, hwirq, priv->irqchip,
					    (void *)(uintptr_t)tint);
	if (ret)
		return ret;

	return irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, &priv->fwspec[hwirq]);
}

static const struct irq_domain_ops rzg2l_irqc_domain_ops = {
	.alloc = rzg2l_irqc_alloc,
	.free = irq_domain_free_irqs_common,
	.translate = irq_domain_translate_twocell,
};

static int rzg2l_irqc_parse_interrupts(struct rzg2l_irqc_priv *priv,
				       struct device_node *np)
{
	struct of_phandle_args map;
	unsigned int i;
	int ret;

	for (i = 0; i < IRQC_NUM_IRQ; i++) {
		ret = of_irq_parse_one(np, i, &map);
		if (ret)
			return ret;
		of_phandle_args_to_fwspec(np, map.args, map.args_count,
					  &priv->fwspec[i]);
	}

	return 0;
}

static int rzg2l_irqc_common_init(struct device_node *node, struct device_node *parent,
				  const struct irq_chip *irq_chip)
{
	struct platform_device *pdev = of_find_device_by_node(node);
	struct device *dev __free(put_device) = pdev ? &pdev->dev : NULL;
	struct irq_domain *irq_domain, *parent_domain;
	struct reset_control *resetn;
	int ret;

	if (!pdev)
		return -ENODEV;

	parent_domain = irq_find_host(parent);
	if (!parent_domain)
		return dev_err_probe(dev, -ENODEV, "cannot find parent domain\n");

	rzg2l_irqc_data = devm_kzalloc(dev, sizeof(*rzg2l_irqc_data), GFP_KERNEL);
	if (!rzg2l_irqc_data)
		return -ENOMEM;

	rzg2l_irqc_data->irqchip = irq_chip;

	rzg2l_irqc_data->base = devm_of_iomap(dev, dev->of_node, 0, NULL);
	if (IS_ERR(rzg2l_irqc_data->base))
		return PTR_ERR(rzg2l_irqc_data->base);

	ret = rzg2l_irqc_parse_interrupts(rzg2l_irqc_data, node);
	if (ret)
		return dev_err_probe(dev, ret, "cannot parse interrupts: %d\n", ret);

	resetn = devm_reset_control_get_exclusive_deasserted(dev, NULL);
	if (IS_ERR(resetn)) {
		return dev_err_probe(dev, PTR_ERR(resetn),
				     "failed to acquire deasserted reset: %d\n", ret);
	}

	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return dev_err_probe(dev, ret, "devm_pm_runtime_enable failed: %d\n", ret);

	ret = pm_runtime_resume_and_get(dev);
	if (ret)
		return dev_err_probe(dev, ret, "pm_runtime_resume_and_get failed: %d\n", ret);

	raw_spin_lock_init(&rzg2l_irqc_data->lock);

	irq_domain = irq_domain_create_hierarchy(parent_domain, 0, IRQC_NUM_IRQ, dev_fwnode(dev),
						 &rzg2l_irqc_domain_ops, rzg2l_irqc_data);
	if (!irq_domain) {
		pm_runtime_put(dev);
		return dev_err_probe(dev, -ENOMEM, "failed to add irq domain\n");
	}

	register_syscore_ops(&rzg2l_irqc_syscore_ops);

	/*
	 * Prevent the cleanup function from invoking put_device by assigning
	 * NULL to dev.
	 *
	 * make coccicheck will complain about missing put_device calls, but
	 * those are false positives, as dev will be automatically "put" via
	 * __free_put_device on the failing path.
	 * On the successful path we don't actually want to "put" dev.
	 */
	dev = NULL;

	return 0;
}

static int __init rzg2l_irqc_init(struct device_node *node,
				  struct device_node *parent)
{
	return rzg2l_irqc_common_init(node, parent, &rzg2l_irqc_chip);
}

static int __init rzfive_irqc_init(struct device_node *node,
				   struct device_node *parent)
{
	return rzg2l_irqc_common_init(node, parent, &rzfive_irqc_chip);
}

IRQCHIP_PLATFORM_DRIVER_BEGIN(rzg2l_irqc)
IRQCHIP_MATCH("renesas,rzg2l-irqc", rzg2l_irqc_init)
IRQCHIP_MATCH("renesas,r9a07g043f-irqc", rzfive_irqc_init)
IRQCHIP_PLATFORM_DRIVER_END(rzg2l_irqc)
MODULE_AUTHOR("Lad Prabhakar <prabhakar.mahadev-lad.rj@bp.renesas.com>");
MODULE_DESCRIPTION("Renesas RZ/G2L IRQC Driver");
