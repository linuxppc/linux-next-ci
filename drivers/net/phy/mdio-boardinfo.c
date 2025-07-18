// SPDX-License-Identifier: GPL-2.0+
/*
 * mdio-boardinfo - Collect pre-declarations for MDIO devices
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/phy.h>
#include <linux/slab.h>

#include "mdio-boardinfo.h"

static LIST_HEAD(mdio_board_list);
static DEFINE_MUTEX(mdio_board_lock);

struct mdio_board_entry {
	struct list_head	list;
	struct mdio_board_info	board_info;
};

/**
 * mdiobus_setup_mdiodev_from_board_info - create and setup MDIO devices
 * from pre-collected board specific MDIO information
 * @bus: Bus the board_info belongs to
 * @cb: Callback to create device on bus
 * Context: can sleep
 */
void mdiobus_setup_mdiodev_from_board_info(struct mii_bus *bus,
					   int (*cb)
					   (struct mii_bus *bus,
					    struct mdio_board_info *bi))
{
	struct mdio_board_entry *be, *tmp;

	mutex_lock(&mdio_board_lock);
	list_for_each_entry_safe(be, tmp, &mdio_board_list, list) {
		struct mdio_board_info *bi = &be->board_info;

		if (strcmp(bus->id, bi->bus_id))
			continue;

		mutex_unlock(&mdio_board_lock);
		cb(bus, bi);
		mutex_lock(&mdio_board_lock);
	}
	mutex_unlock(&mdio_board_lock);
}
EXPORT_SYMBOL(mdiobus_setup_mdiodev_from_board_info);

/**
 * mdiobus_register_board_info - register MDIO devices for a given board
 * @info: array of devices descriptors
 * @n: number of descriptors provided
 * Context: can sleep
 *
 * The board info passed can be marked with __initdata but be pointers
 * such as platform_data etc. are copied as-is
 */
int mdiobus_register_board_info(const struct mdio_board_info *info,
				unsigned int n)
{
	struct mdio_board_entry *be;

	be = kcalloc(n, sizeof(*be), GFP_KERNEL);
	if (!be)
		return -ENOMEM;

	for (int i = 0; i < n; i++, be++) {
		be->board_info = info[i];
		mutex_lock(&mdio_board_lock);
		list_add_tail(&be->list, &mdio_board_list);
		mutex_unlock(&mdio_board_lock);
	}

	return 0;
}
EXPORT_SYMBOL(mdiobus_register_board_info);
