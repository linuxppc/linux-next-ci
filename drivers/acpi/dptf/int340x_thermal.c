// SPDX-License-Identifier: GPL-2.0-only
/*
 * ACPI support for int340x thermal drivers
 *
 * Copyright (C) 2014, Intel Corporation
 * Authors: Zhang Rui <rui.zhang@intel.com>
 */

#include <linux/acpi.h>
#include <linux/module.h>

#include "../internal.h"

#define INT3401_DEVICE 0X01
static const struct acpi_device_id int340x_thermal_device_ids[] = {
	{"INT3400"},
	{"INT3401", INT3401_DEVICE},
	{"INT3402"},
	{"INT3403"},
	{"INT3404"},
	{"INT3406"},
	{"INT3407"},
	{"INT3408"},
	{"INT3409"},
	{"INT340A"},
	{"INT340B"},
	{"INT3532"},
	{"INTC1040"},
	{"INTC1041"},
	{"INTC1042"},
	{"INTC1043"},
	{"INTC1044"},
	{"INTC1045"},
	{"INTC1046"},
	{"INTC1047"},
	{"INTC1048"},
	{"INTC1049"},
	{"INTC1050"},
	{"INTC1060"},
	{"INTC1061"},
	{"INTC1062"},
	{"INTC1063"},
	{"INTC1064"},
	{"INTC1065"},
	{"INTC1066"},
	{"INTC1068"},
	{"INTC1069"},
	{"INTC106A"},
	{"INTC106B"},
	{"INTC106C"},
	{"INTC106D"},
	{"INTC10A0"},
	{"INTC10A1"},
	{"INTC10A2"},
	{"INTC10A3"},
	{"INTC10A4"},
	{"INTC10A5"},
	{"INTC10D4"},
	{"INTC10D5"},
	{"INTC10D6"},
	{"INTC10D7"},
	{"INTC10D8"},
	{"INTC10D9"},
	{"INTC10FC"},
	{"INTC10FD"},
	{"INTC10FE"},
	{"INTC10FF"},
	{"INTC1100"},
	{"INTC1101"},
	{"INTC1102"},
	{""},
};

static int int340x_thermal_handler_attach(struct acpi_device *adev,
					const struct acpi_device_id *id)
{
	if (IS_ENABLED(CONFIG_INT340X_THERMAL))
		acpi_create_platform_device(adev, NULL);
	/* Intel SoC DTS thermal driver needs INT3401 to set IRQ descriptor */
	else if (IS_ENABLED(CONFIG_INTEL_SOC_DTS_THERMAL) &&
		 id->driver_data == INT3401_DEVICE)
		acpi_create_platform_device(adev, NULL);
	return 1;
}

static struct acpi_scan_handler int340x_thermal_handler = {
	.ids = int340x_thermal_device_ids,
	.attach = int340x_thermal_handler_attach,
};

void __init acpi_int340x_thermal_init(void)
{
	acpi_scan_add_handler(&int340x_thermal_handler);
}
