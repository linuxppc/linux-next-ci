// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Driver for Goodix Touchscreens
 *
 *  Copyright (c) 2014 Red Hat Inc.
 *  Copyright (c) 2015 K. Merker <merker@debian.org>
 *
 *  This code is based on gt9xx.c authored by andrew@goodix.com:
 *
 *  2010 - 2012 Goodix Technology.
 */


#include <linux/kernel.h>
#include <linux/dmi.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/platform_data/x86/soc.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/unaligned.h>
#include "goodix.h"

#define GOODIX_GPIO_INT_NAME		"irq"
#define GOODIX_GPIO_RST_NAME		"reset"

#define GOODIX_MAX_HEIGHT		4096
#define GOODIX_MAX_WIDTH		4096
#define GOODIX_INT_TRIGGER		1
#define GOODIX_CONTACT_SIZE		8
#define GOODIX_MAX_CONTACT_SIZE		9
#define GOODIX_MAX_CONTACTS		10

#define GOODIX_CONFIG_MIN_LENGTH	186
#define GOODIX_CONFIG_911_LENGTH	186
#define GOODIX_CONFIG_967_LENGTH	228
#define GOODIX_CONFIG_GT9X_LENGTH	240

#define GOODIX_BUFFER_STATUS_READY	BIT(7)
#define GOODIX_HAVE_KEY			BIT(4)
#define GOODIX_BUFFER_STATUS_TIMEOUT	20

#define RESOLUTION_LOC			1
#define MAX_CONTACTS_LOC		5
#define TRIGGER_LOC			6

#define GOODIX_POLL_INTERVAL_MS		17	/* 17ms = 60fps */

/* Our special handling for GPIO accesses through ACPI is x86 specific */
#if defined CONFIG_X86 && defined CONFIG_ACPI
#define ACPI_GPIO_SUPPORT
#endif

struct goodix_chip_id {
	const char *id;
	const struct goodix_chip_data *data;
};

static int goodix_check_cfg_8(struct goodix_ts_data *ts,
			      const u8 *cfg, int len);
static int goodix_check_cfg_16(struct goodix_ts_data *ts,
			       const u8 *cfg, int len);
static void goodix_calc_cfg_checksum_8(struct goodix_ts_data *ts);
static void goodix_calc_cfg_checksum_16(struct goodix_ts_data *ts);

static const struct goodix_chip_data gt1x_chip_data = {
	.config_addr		= GOODIX_GT1X_REG_CONFIG_DATA,
	.config_len		= GOODIX_CONFIG_GT9X_LENGTH,
	.check_config		= goodix_check_cfg_16,
	.calc_config_checksum	= goodix_calc_cfg_checksum_16,
};

static const struct goodix_chip_data gt911_chip_data = {
	.config_addr		= GOODIX_GT9X_REG_CONFIG_DATA,
	.config_len		= GOODIX_CONFIG_911_LENGTH,
	.check_config		= goodix_check_cfg_8,
	.calc_config_checksum	= goodix_calc_cfg_checksum_8,
};

static const struct goodix_chip_data gt967_chip_data = {
	.config_addr		= GOODIX_GT9X_REG_CONFIG_DATA,
	.config_len		= GOODIX_CONFIG_967_LENGTH,
	.check_config		= goodix_check_cfg_8,
	.calc_config_checksum	= goodix_calc_cfg_checksum_8,
};

static const struct goodix_chip_data gt9x_chip_data = {
	.config_addr		= GOODIX_GT9X_REG_CONFIG_DATA,
	.config_len		= GOODIX_CONFIG_GT9X_LENGTH,
	.check_config		= goodix_check_cfg_8,
	.calc_config_checksum	= goodix_calc_cfg_checksum_8,
};

static const struct goodix_chip_id goodix_chip_ids[] = {
	{ .id = "1151", .data = &gt1x_chip_data },
	{ .id = "1158", .data = &gt1x_chip_data },
	{ .id = "5663", .data = &gt1x_chip_data },
	{ .id = "5688", .data = &gt1x_chip_data },
	{ .id = "917S", .data = &gt1x_chip_data },
	{ .id = "9286", .data = &gt1x_chip_data },

	{ .id = "911", .data = &gt911_chip_data },
	{ .id = "9271", .data = &gt911_chip_data },
	{ .id = "9110", .data = &gt911_chip_data },
	{ .id = "9111", .data = &gt911_chip_data },
	{ .id = "927", .data = &gt911_chip_data },
	{ .id = "928", .data = &gt911_chip_data },

	{ .id = "912", .data = &gt967_chip_data },
	{ .id = "9147", .data = &gt967_chip_data },
	{ .id = "967", .data = &gt967_chip_data },
	{ }
};

static const unsigned long goodix_irq_flags[] = {
	IRQ_TYPE_EDGE_RISING,
	IRQ_TYPE_EDGE_FALLING,
	IRQ_TYPE_LEVEL_LOW,
	IRQ_TYPE_LEVEL_HIGH,
};

static const struct dmi_system_id nine_bytes_report[] = {
#if defined(CONFIG_DMI) && defined(CONFIG_X86)
	{
		/* Lenovo Yoga Book X90F / X90L */
		.matches = {
			DMI_EXACT_MATCH(DMI_SYS_VENDOR, "Intel Corporation"),
			DMI_EXACT_MATCH(DMI_PRODUCT_NAME, "CHERRYVIEW D1 PLATFORM"),
			DMI_EXACT_MATCH(DMI_PRODUCT_VERSION, "YETI-11"),
		}
	},
	{
		/* Lenovo Yoga Book X91F / X91L */
		.matches = {
			/* Non exact match to match F + L versions */
			DMI_MATCH(DMI_PRODUCT_NAME, "Lenovo YB1-X91"),
		}
	},
#endif
	{}
};

/*
 * Those tablets have their x coordinate inverted
 */
static const struct dmi_system_id inverted_x_screen[] = {
#if defined(CONFIG_DMI) && defined(CONFIG_X86)
	{
		.ident = "Cube I15-TC",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "Cube"),
			DMI_MATCH(DMI_PRODUCT_NAME, "I15-TC")
		},
	},
#endif
	{}
};

/**
 * goodix_i2c_read - read data from a register of the i2c slave device.
 *
 * @client: i2c device.
 * @reg: the register to read from.
 * @buf: raw write data buffer.
 * @len: length of the buffer to write
 */
int goodix_i2c_read(struct i2c_client *client, u16 reg, u8 *buf, int len)
{
	struct i2c_msg msgs[2];
	__be16 wbuf = cpu_to_be16(reg);
	int ret;

	msgs[0].flags = 0;
	msgs[0].addr  = client->addr;
	msgs[0].len   = 2;
	msgs[0].buf   = (u8 *)&wbuf;

	msgs[1].flags = I2C_M_RD;
	msgs[1].addr  = client->addr;
	msgs[1].len   = len;
	msgs[1].buf   = buf;

	ret = i2c_transfer(client->adapter, msgs, 2);
	if (ret >= 0)
		ret = (ret == ARRAY_SIZE(msgs) ? 0 : -EIO);

	if (ret)
		dev_err(&client->dev, "Error reading %d bytes from 0x%04x: %d\n",
			len, reg, ret);
	return ret;
}

/**
 * goodix_i2c_write - write data to a register of the i2c slave device.
 *
 * @client: i2c device.
 * @reg: the register to write to.
 * @buf: raw data buffer to write.
 * @len: length of the buffer to write
 */
int goodix_i2c_write(struct i2c_client *client, u16 reg, const u8 *buf, int len)
{
	u8 *addr_buf;
	struct i2c_msg msg;
	int ret;

	addr_buf = kmalloc(len + 2, GFP_KERNEL);
	if (!addr_buf)
		return -ENOMEM;

	addr_buf[0] = reg >> 8;
	addr_buf[1] = reg & 0xFF;
	memcpy(&addr_buf[2], buf, len);

	msg.flags = 0;
	msg.addr = client->addr;
	msg.buf = addr_buf;
	msg.len = len + 2;

	ret = i2c_transfer(client->adapter, &msg, 1);
	if (ret >= 0)
		ret = (ret == 1 ? 0 : -EIO);

	kfree(addr_buf);

	if (ret)
		dev_err(&client->dev, "Error writing %d bytes to 0x%04x: %d\n",
			len, reg, ret);
	return ret;
}

int goodix_i2c_write_u8(struct i2c_client *client, u16 reg, u8 value)
{
	return goodix_i2c_write(client, reg, &value, sizeof(value));
}

static const struct goodix_chip_data *goodix_get_chip_data(const char *id)
{
	unsigned int i;

	for (i = 0; goodix_chip_ids[i].id; i++) {
		if (!strcmp(goodix_chip_ids[i].id, id))
			return goodix_chip_ids[i].data;
	}

	return &gt9x_chip_data;
}

static int goodix_ts_read_input_report(struct goodix_ts_data *ts, u8 *data)
{
	unsigned long max_timeout;
	int touch_num;
	int error;
	u16 addr = GOODIX_READ_COOR_ADDR;
	/*
	 * We are going to read 1-byte header,
	 * ts->contact_size * max(1, touch_num) bytes of coordinates
	 * and 1-byte footer which contains the touch-key code.
	 */
	const int header_contact_keycode_size = 1 + ts->contact_size + 1;

	/*
	 * The 'buffer status' bit, which indicates that the data is valid, is
	 * not set as soon as the interrupt is raised, but slightly after.
	 * This takes around 10 ms to happen, so we poll for 20 ms.
	 */
	max_timeout = jiffies + msecs_to_jiffies(GOODIX_BUFFER_STATUS_TIMEOUT);
	do {
		error = goodix_i2c_read(ts->client, addr, data,
					header_contact_keycode_size);
		if (error)
			return error;

		if (data[0] & GOODIX_BUFFER_STATUS_READY) {
			touch_num = data[0] & 0x0f;
			if (touch_num > ts->max_touch_num)
				return -EPROTO;

			if (touch_num > 1) {
				addr += header_contact_keycode_size;
				data += header_contact_keycode_size;
				error = goodix_i2c_read(ts->client,
						addr, data,
						ts->contact_size *
							(touch_num - 1));
				if (error)
					return error;
			}

			return touch_num;
		}

		if (data[0] == 0 && ts->firmware_name) {
			if (goodix_handle_fw_request(ts))
				return 0;
		}

		usleep_range(1000, 2000); /* Poll every 1 - 2 ms */
	} while (time_before(jiffies, max_timeout));

	/*
	 * The Goodix panel will send spurious interrupts after a
	 * 'finger up' event, which will always cause a timeout.
	 */
	return -ENOMSG;
}

static int goodix_create_pen_input(struct goodix_ts_data *ts)
{
	struct device *dev = &ts->client->dev;
	struct input_dev *input;

	input = devm_input_allocate_device(dev);
	if (!input)
		return -ENOMEM;

	input_copy_abs(input, ABS_X, ts->input_dev, ABS_MT_POSITION_X);
	input_copy_abs(input, ABS_Y, ts->input_dev, ABS_MT_POSITION_Y);
	/*
	 * The resolution of these touchscreens is about 10 units/mm, the actual
	 * resolution does not matter much since we set INPUT_PROP_DIRECT.
	 * Userspace wants something here though, so just set it to 10 units/mm.
	 */
	input_abs_set_res(input, ABS_X, 10);
	input_abs_set_res(input, ABS_Y, 10);
	input_set_abs_params(input, ABS_PRESSURE, 0, 255, 0, 0);

	input_set_capability(input, EV_KEY, BTN_TOUCH);
	input_set_capability(input, EV_KEY, BTN_TOOL_PEN);
	input_set_capability(input, EV_KEY, BTN_STYLUS);
	input_set_capability(input, EV_KEY, BTN_STYLUS2);
	__set_bit(INPUT_PROP_DIRECT, input->propbit);

	input->name = "Goodix Active Pen";
	input->phys = "input/pen";
	input->id.bustype = BUS_I2C;
	input->id.vendor = 0x0416;
	if (kstrtou16(ts->id, 10, &input->id.product))
		input->id.product = 0x1001;
	input->id.version = ts->version;

	ts->input_pen = input;
	return 0;
}

static void goodix_ts_report_pen_down(struct goodix_ts_data *ts, u8 *data)
{
	int input_x, input_y, input_w, error;
	u8 key_value;

	if (!ts->pen_input_registered) {
		error = input_register_device(ts->input_pen);
		ts->pen_input_registered = (error == 0) ? 1 : error;
	}

	if (ts->pen_input_registered < 0)
		return;

	if (ts->contact_size == 9) {
		input_x = get_unaligned_le16(&data[4]);
		input_y = get_unaligned_le16(&data[6]);
		input_w = get_unaligned_le16(&data[8]);
	} else {
		input_x = get_unaligned_le16(&data[2]);
		input_y = get_unaligned_le16(&data[4]);
		input_w = get_unaligned_le16(&data[6]);
	}

	touchscreen_report_pos(ts->input_pen, &ts->prop, input_x, input_y, false);
	input_report_abs(ts->input_pen, ABS_PRESSURE, input_w);

	input_report_key(ts->input_pen, BTN_TOUCH, 1);
	input_report_key(ts->input_pen, BTN_TOOL_PEN, 1);

	if (data[0] & GOODIX_HAVE_KEY) {
		key_value = data[1 + ts->contact_size];
		input_report_key(ts->input_pen, BTN_STYLUS, key_value & 0x10);
		input_report_key(ts->input_pen, BTN_STYLUS2, key_value & 0x20);
	} else {
		input_report_key(ts->input_pen, BTN_STYLUS, 0);
		input_report_key(ts->input_pen, BTN_STYLUS2, 0);
	}

	input_sync(ts->input_pen);
}

static void goodix_ts_report_pen_up(struct goodix_ts_data *ts)
{
	if (!ts->input_pen)
		return;

	input_report_key(ts->input_pen, BTN_TOUCH, 0);
	input_report_key(ts->input_pen, BTN_TOOL_PEN, 0);
	input_report_key(ts->input_pen, BTN_STYLUS, 0);
	input_report_key(ts->input_pen, BTN_STYLUS2, 0);

	input_sync(ts->input_pen);
}

static void goodix_ts_report_touch_8b(struct goodix_ts_data *ts, u8 *coor_data)
{
	int id = coor_data[0] & 0x0F;
	int input_x = get_unaligned_le16(&coor_data[1]);
	int input_y = get_unaligned_le16(&coor_data[3]);
	int input_w = get_unaligned_le16(&coor_data[5]);

	input_mt_slot(ts->input_dev, id);
	input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, true);
	touchscreen_report_pos(ts->input_dev, &ts->prop,
			       input_x, input_y, true);
	input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, input_w);
	input_report_abs(ts->input_dev, ABS_MT_WIDTH_MAJOR, input_w);
}

static void goodix_ts_report_touch_9b(struct goodix_ts_data *ts, u8 *coor_data)
{
	int id = coor_data[1] & 0x0F;
	int input_x = get_unaligned_le16(&coor_data[3]);
	int input_y = get_unaligned_le16(&coor_data[5]);
	int input_w = get_unaligned_le16(&coor_data[7]);

	input_mt_slot(ts->input_dev, id);
	input_mt_report_slot_state(ts->input_dev, MT_TOOL_FINGER, true);
	touchscreen_report_pos(ts->input_dev, &ts->prop,
			       input_x, input_y, true);
	input_report_abs(ts->input_dev, ABS_MT_TOUCH_MAJOR, input_w);
	input_report_abs(ts->input_dev, ABS_MT_WIDTH_MAJOR, input_w);
}

static void goodix_ts_release_keys(struct goodix_ts_data *ts)
{
	int i;

	for (i = 0; i < GOODIX_MAX_KEYS; i++)
		input_report_key(ts->input_dev, ts->keymap[i], 0);
}

static void goodix_ts_report_key(struct goodix_ts_data *ts, u8 *data)
{
	int touch_num;
	u8 key_value;
	int i;

	if (data[0] & GOODIX_HAVE_KEY) {
		touch_num = data[0] & 0x0f;
		key_value = data[1 + ts->contact_size * touch_num];
		for (i = 0; i < GOODIX_MAX_KEYS; i++)
			if (key_value & BIT(i))
				input_report_key(ts->input_dev,
						 ts->keymap[i], 1);
	} else {
		goodix_ts_release_keys(ts);
	}
}

/**
 * goodix_process_events - Process incoming events
 *
 * @ts: our goodix_ts_data pointer
 *
 * Called when the IRQ is triggered. Read the current device state, and push
 * the input events to the user space.
 */
static void goodix_process_events(struct goodix_ts_data *ts)
{
	u8  point_data[2 + GOODIX_MAX_CONTACT_SIZE * GOODIX_MAX_CONTACTS];
	int touch_num;
	int i;

	touch_num = goodix_ts_read_input_report(ts, point_data);
	if (touch_num < 0)
		return;

	/* The pen being down is always reported as a single touch */
	if (touch_num == 1 && (point_data[1] & 0x80)) {
		goodix_ts_report_pen_down(ts, point_data);
		goodix_ts_release_keys(ts);
		goto sync; /* Release any previously registered touches */
	} else {
		goodix_ts_report_pen_up(ts);
	}

	goodix_ts_report_key(ts, point_data);

	for (i = 0; i < touch_num; i++)
		if (ts->contact_size == 9)
			goodix_ts_report_touch_9b(ts,
				&point_data[1 + ts->contact_size * i]);
		else
			goodix_ts_report_touch_8b(ts,
				&point_data[1 + ts->contact_size * i]);

sync:
	input_mt_sync_frame(ts->input_dev);
	input_sync(ts->input_dev);
}

static void goodix_ts_work_i2c_poll(struct input_dev *input)
{
	struct goodix_ts_data *ts = input_get_drvdata(input);

	goodix_process_events(ts);
	goodix_i2c_write_u8(ts->client, GOODIX_READ_COOR_ADDR, 0);
}

/**
 * goodix_ts_irq_handler - The IRQ handler
 *
 * @irq: interrupt number.
 * @dev_id: private data pointer.
 */
static irqreturn_t goodix_ts_irq_handler(int irq, void *dev_id)
{
	struct goodix_ts_data *ts = dev_id;

	goodix_process_events(ts);
	goodix_i2c_write_u8(ts->client, GOODIX_READ_COOR_ADDR, 0);

	return IRQ_HANDLED;
}

static void goodix_enable_irq(struct goodix_ts_data *ts)
{
	if (ts->client->irq)
		enable_irq(ts->client->irq);
}

static void goodix_disable_irq(struct goodix_ts_data *ts)
{
	if (ts->client->irq)
		disable_irq(ts->client->irq);
}

static void goodix_free_irq(struct goodix_ts_data *ts)
{
	if (ts->client->irq)
		devm_free_irq(&ts->client->dev, ts->client->irq, ts);
}

static int goodix_request_irq(struct goodix_ts_data *ts)
{
	if (!ts->client->irq)
		return 0;

	return devm_request_threaded_irq(&ts->client->dev, ts->client->irq,
					 NULL, goodix_ts_irq_handler,
					 ts->irq_flags, ts->client->name, ts);
}

static int goodix_check_cfg_8(struct goodix_ts_data *ts, const u8 *cfg, int len)
{
	int i, raw_cfg_len = len - 2;
	u8 check_sum = 0;

	for (i = 0; i < raw_cfg_len; i++)
		check_sum += cfg[i];
	check_sum = (~check_sum) + 1;
	if (check_sum != cfg[raw_cfg_len]) {
		dev_err(&ts->client->dev,
			"The checksum of the config fw is not correct");
		return -EINVAL;
	}

	if (cfg[raw_cfg_len + 1] != 1) {
		dev_err(&ts->client->dev,
			"Config fw must have Config_Fresh register set");
		return -EINVAL;
	}

	return 0;
}

static void goodix_calc_cfg_checksum_8(struct goodix_ts_data *ts)
{
	int i, raw_cfg_len = ts->chip->config_len - 2;
	u8 check_sum = 0;

	for (i = 0; i < raw_cfg_len; i++)
		check_sum += ts->config[i];
	check_sum = (~check_sum) + 1;

	ts->config[raw_cfg_len] = check_sum;
	ts->config[raw_cfg_len + 1] = 1; /* Set "config_fresh" bit */
}

static int goodix_check_cfg_16(struct goodix_ts_data *ts, const u8 *cfg,
			       int len)
{
	int i, raw_cfg_len = len - 3;
	u16 check_sum = 0;

	for (i = 0; i < raw_cfg_len; i += 2)
		check_sum += get_unaligned_be16(&cfg[i]);
	check_sum = (~check_sum) + 1;
	if (check_sum != get_unaligned_be16(&cfg[raw_cfg_len])) {
		dev_err(&ts->client->dev,
			"The checksum of the config fw is not correct");
		return -EINVAL;
	}

	if (cfg[raw_cfg_len + 2] != 1) {
		dev_err(&ts->client->dev,
			"Config fw must have Config_Fresh register set");
		return -EINVAL;
	}

	return 0;
}

static void goodix_calc_cfg_checksum_16(struct goodix_ts_data *ts)
{
	int i, raw_cfg_len = ts->chip->config_len - 3;
	u16 check_sum = 0;

	for (i = 0; i < raw_cfg_len; i += 2)
		check_sum += get_unaligned_be16(&ts->config[i]);
	check_sum = (~check_sum) + 1;

	put_unaligned_be16(check_sum, &ts->config[raw_cfg_len]);
	ts->config[raw_cfg_len + 2] = 1; /* Set "config_fresh" bit */
}

/**
 * goodix_check_cfg - Checks if config fw is valid
 *
 * @ts: goodix_ts_data pointer
 * @cfg: firmware config data
 * @len: config data length
 */
static int goodix_check_cfg(struct goodix_ts_data *ts, const u8 *cfg, int len)
{
	if (len < GOODIX_CONFIG_MIN_LENGTH ||
	    len > GOODIX_CONFIG_MAX_LENGTH) {
		dev_err(&ts->client->dev,
			"The length of the config fw is not correct");
		return -EINVAL;
	}

	return ts->chip->check_config(ts, cfg, len);
}

/**
 * goodix_send_cfg - Write fw config to device
 *
 * @ts: goodix_ts_data pointer
 * @cfg: config firmware to write to device
 * @len: config data length
 */
int goodix_send_cfg(struct goodix_ts_data *ts, const u8 *cfg, int len)
{
	int error;

	error = goodix_check_cfg(ts, cfg, len);
	if (error)
		return error;

	error = goodix_i2c_write(ts->client, ts->chip->config_addr, cfg, len);
	if (error)
		return error;

	dev_dbg(&ts->client->dev, "Config sent successfully.");

	/* Let the firmware reconfigure itself, so sleep for 10ms */
	usleep_range(10000, 11000);

	return 0;
}

#ifdef ACPI_GPIO_SUPPORT
static int goodix_pin_acpi_direction_input(struct goodix_ts_data *ts)
{
	acpi_handle handle = ACPI_HANDLE(&ts->client->dev);
	acpi_status status;

	status = acpi_evaluate_object(handle, "INTI", NULL, NULL);
	return ACPI_SUCCESS(status) ? 0 : -EIO;
}

static int goodix_pin_acpi_output_method(struct goodix_ts_data *ts, int value)
{
	acpi_handle handle = ACPI_HANDLE(&ts->client->dev);
	acpi_status status;

	status = acpi_execute_simple_method(handle, "INTO", value);
	return ACPI_SUCCESS(status) ? 0 : -EIO;
}
#else
static int goodix_pin_acpi_direction_input(struct goodix_ts_data *ts)
{
	dev_err(&ts->client->dev,
		"%s called on device without ACPI support\n", __func__);
	return -EINVAL;
}

static int goodix_pin_acpi_output_method(struct goodix_ts_data *ts, int value)
{
	dev_err(&ts->client->dev,
		"%s called on device without ACPI support\n", __func__);
	return -EINVAL;
}
#endif

static int goodix_irq_direction_output(struct goodix_ts_data *ts, int value)
{
	switch (ts->irq_pin_access_method) {
	case IRQ_PIN_ACCESS_NONE:
		dev_err(&ts->client->dev,
			"%s called without an irq_pin_access_method set\n",
			__func__);
		return -EINVAL;
	case IRQ_PIN_ACCESS_GPIO:
		return gpiod_direction_output(ts->gpiod_int, value);
	case IRQ_PIN_ACCESS_ACPI_GPIO:
		/*
		 * The IRQ pin triggers on a falling edge, so its gets marked
		 * as active-low, use output_raw to avoid the value inversion.
		 */
		return gpiod_direction_output_raw(ts->gpiod_int, value);
	case IRQ_PIN_ACCESS_ACPI_METHOD:
		return goodix_pin_acpi_output_method(ts, value);
	}

	return -EINVAL; /* Never reached */
}

static int goodix_irq_direction_input(struct goodix_ts_data *ts)
{
	switch (ts->irq_pin_access_method) {
	case IRQ_PIN_ACCESS_NONE:
		dev_err(&ts->client->dev,
			"%s called without an irq_pin_access_method set\n",
			__func__);
		return -EINVAL;
	case IRQ_PIN_ACCESS_GPIO:
		return gpiod_direction_input(ts->gpiod_int);
	case IRQ_PIN_ACCESS_ACPI_GPIO:
		return gpiod_direction_input(ts->gpiod_int);
	case IRQ_PIN_ACCESS_ACPI_METHOD:
		return goodix_pin_acpi_direction_input(ts);
	}

	return -EINVAL; /* Never reached */
}

int goodix_int_sync(struct goodix_ts_data *ts)
{
	int error;

	error = goodix_irq_direction_output(ts, 0);
	if (error)
		goto error;

	msleep(50);				/* T5: 50ms */

	error = goodix_irq_direction_input(ts);
	if (error)
		goto error;

	return 0;

error:
	dev_err(&ts->client->dev, "Controller irq sync failed.\n");
	return error;
}

/**
 * goodix_reset_no_int_sync - Reset device, leaving interrupt line in output mode
 *
 * @ts: goodix_ts_data pointer
 */
int goodix_reset_no_int_sync(struct goodix_ts_data *ts)
{
	int error;

	/* begin select I2C slave addr */
	error = gpiod_direction_output(ts->gpiod_rst, 0);
	if (error)
		goto error;

	msleep(20);				/* T2: > 10ms */

	/* HIGH: 0x28/0x29, LOW: 0xBA/0xBB */
	error = goodix_irq_direction_output(ts, ts->client->addr == 0x14);
	if (error)
		goto error;

	usleep_range(100, 2000);		/* T3: > 100us */

	error = gpiod_direction_output(ts->gpiod_rst, 1);
	if (error)
		goto error;

	usleep_range(6000, 10000);		/* T4: > 5ms */

	/*
	 * Put the reset pin back in to input / high-impedance mode to save
	 * power. Only do this in the non ACPI case since some ACPI boards
	 * don't have a pull-up, so there the reset pin must stay active-high.
	 */
	if (ts->irq_pin_access_method == IRQ_PIN_ACCESS_GPIO) {
		error = gpiod_direction_input(ts->gpiod_rst);
		if (error)
			goto error;
	}

	return 0;

error:
	dev_err(&ts->client->dev, "Controller reset failed.\n");
	return error;
}

/**
 * goodix_reset - Reset device during power on
 *
 * @ts: goodix_ts_data pointer
 */
static int goodix_reset(struct goodix_ts_data *ts)
{
	int error;

	error = goodix_reset_no_int_sync(ts);
	if (error)
		return error;

	return goodix_int_sync(ts);
}

#ifdef ACPI_GPIO_SUPPORT
static const struct acpi_gpio_params first_gpio = { 0, 0, false };
static const struct acpi_gpio_params second_gpio = { 1, 0, false };

static const struct acpi_gpio_mapping acpi_goodix_int_first_gpios[] = {
	{ GOODIX_GPIO_INT_NAME "-gpios", &first_gpio, 1 },
	{ GOODIX_GPIO_RST_NAME "-gpios", &second_gpio, 1 },
	{ },
};

static const struct acpi_gpio_mapping acpi_goodix_int_last_gpios[] = {
	{ GOODIX_GPIO_RST_NAME "-gpios", &first_gpio, 1 },
	{ GOODIX_GPIO_INT_NAME "-gpios", &second_gpio, 1 },
	{ },
};

static const struct acpi_gpio_mapping acpi_goodix_reset_only_gpios[] = {
	{ GOODIX_GPIO_RST_NAME "-gpios", &first_gpio, 1 },
	{ },
};

static int goodix_resource(struct acpi_resource *ares, void *data)
{
	struct goodix_ts_data *ts = data;
	struct device *dev = &ts->client->dev;
	struct acpi_resource_gpio *gpio;

	if (acpi_gpio_get_irq_resource(ares, &gpio)) {
		if (ts->gpio_int_idx == -1) {
			ts->gpio_int_idx = ts->gpio_count;
		} else {
			dev_err(dev, "More then one GpioInt resource, ignoring ACPI GPIO resources\n");
			ts->gpio_int_idx = -2;
		}
		ts->gpio_count++;
	} else if (acpi_gpio_get_io_resource(ares, &gpio))
		ts->gpio_count++;

	return 0;
}

/*
 * This function gets called in case we fail to get the irq GPIO directly
 * because the ACPI tables lack GPIO-name to APCI _CRS index mappings
 * (no _DSD UUID daffd814-6eba-4d8c-8a91-bc9bbf4aa301 data).
 * In that case we add our own mapping and then goodix_get_gpio_config()
 * retries to get the GPIOs based on the added mapping.
 */
static int goodix_add_acpi_gpio_mappings(struct goodix_ts_data *ts)
{
	const struct acpi_gpio_mapping *gpio_mapping = NULL;
	struct device *dev = &ts->client->dev;
	LIST_HEAD(resources);
	int irq, ret;

	ts->gpio_count = 0;
	ts->gpio_int_idx = -1;
	ret = acpi_dev_get_resources(ACPI_COMPANION(dev), &resources,
				     goodix_resource, ts);
	if (ret < 0) {
		dev_err(dev, "Error getting ACPI resources: %d\n", ret);
		return ret;
	}

	acpi_dev_free_resource_list(&resources);

	/*
	 * CHT devices should have a GpioInt + a regular GPIO ACPI resource.
	 * Some CHT devices have a bug (where the also is bogus Interrupt
	 * resource copied from a previous BYT based generation). i2c-core-acpi
	 * will use the non-working Interrupt resource, fix this up.
	 */
	if (soc_intel_is_cht() && ts->gpio_count == 2 && ts->gpio_int_idx != -1) {
		irq = acpi_dev_gpio_irq_get(ACPI_COMPANION(dev), 0);
		if (irq > 0 && irq != ts->client->irq) {
			dev_warn(dev, "Overriding IRQ %d -> %d\n", ts->client->irq, irq);
			ts->client->irq = irq;
		}
	}

	/* Some devices with gpio_int_idx 0 list a third unused GPIO */
	if ((ts->gpio_count == 2 || ts->gpio_count == 3) && ts->gpio_int_idx == 0) {
		ts->irq_pin_access_method = IRQ_PIN_ACCESS_ACPI_GPIO;
		gpio_mapping = acpi_goodix_int_first_gpios;
	} else if (ts->gpio_count == 2 && ts->gpio_int_idx == 1) {
		ts->irq_pin_access_method = IRQ_PIN_ACCESS_ACPI_GPIO;
		gpio_mapping = acpi_goodix_int_last_gpios;
	} else if (ts->gpio_count == 1 && ts->gpio_int_idx == -1 &&
		   acpi_has_method(ACPI_HANDLE(dev), "INTI") &&
		   acpi_has_method(ACPI_HANDLE(dev), "INTO")) {
		dev_info(dev, "Using ACPI INTI and INTO methods for IRQ pin access\n");
		ts->irq_pin_access_method = IRQ_PIN_ACCESS_ACPI_METHOD;
		gpio_mapping = acpi_goodix_reset_only_gpios;
	} else if (soc_intel_is_byt() && ts->gpio_count == 2 && ts->gpio_int_idx == -1) {
		dev_info(dev, "No ACPI GpioInt resource, assuming that the GPIO order is reset, int\n");
		ts->irq_pin_access_method = IRQ_PIN_ACCESS_ACPI_GPIO;
		gpio_mapping = acpi_goodix_int_last_gpios;
	} else if (ts->gpio_count == 1 && ts->gpio_int_idx == 0) {
		/*
		 * On newer devices there is only 1 GpioInt resource and _PS0
		 * does the whole reset sequence for us.
		 */
		acpi_device_fix_up_power(ACPI_COMPANION(dev));

		/*
		 * Before the _PS0 call the int GPIO may have been in output
		 * mode and the call should have put the int GPIO in input mode,
		 * but the GPIO subsys cached state may still think it is
		 * in output mode, causing gpiochip_lock_as_irq() failure.
		 *
		 * Add a mapping for the int GPIO to make the
		 * gpiod_int = gpiod_get(..., GPIOD_IN) call succeed,
		 * which will explicitly set the direction to input.
		 */
		ts->irq_pin_access_method = IRQ_PIN_ACCESS_NONE;
		gpio_mapping = acpi_goodix_int_first_gpios;
	} else {
		dev_warn(dev, "Unexpected ACPI resources: gpio_count %d, gpio_int_idx %d\n",
			 ts->gpio_count, ts->gpio_int_idx);
		/*
		 * On some devices _PS0 does a reset for us and
		 * sometimes this is necessary for things to work.
		 */
		acpi_device_fix_up_power(ACPI_COMPANION(dev));
		return -EINVAL;
	}

	/*
	 * Normally we put the reset pin in input / high-impedance mode to save
	 * power. But some x86/ACPI boards don't have a pull-up, so for the ACPI
	 * case, leave the pin as is. This results in the pin not being touched
	 * at all on x86/ACPI boards, except when needed for error-recover.
	 */
	ts->gpiod_rst_flags = GPIOD_ASIS;

	return devm_acpi_dev_add_driver_gpios(dev, gpio_mapping);
}
#else
static int goodix_add_acpi_gpio_mappings(struct goodix_ts_data *ts)
{
	return -EINVAL;
}
#endif /* CONFIG_X86 && CONFIG_ACPI */

/**
 * goodix_get_gpio_config - Get GPIO config from ACPI/DT
 *
 * @ts: goodix_ts_data pointer
 */
static int goodix_get_gpio_config(struct goodix_ts_data *ts)
{
	struct device *dev;
	struct gpio_desc *gpiod;
	bool added_acpi_mappings = false;

	if (!ts->client)
		return -EINVAL;
	dev = &ts->client->dev;

	/*
	 * By default we request the reset pin as input, leaving it in
	 * high-impedance when not resetting the controller to save power.
	 */
	ts->gpiod_rst_flags = GPIOD_IN;

	ts->avdd28 = devm_regulator_get(dev, "AVDD28");
	if (IS_ERR(ts->avdd28))
		return dev_err_probe(dev, PTR_ERR(ts->avdd28), "Failed to get AVDD28 regulator\n");

	ts->vddio = devm_regulator_get(dev, "VDDIO");
	if (IS_ERR(ts->vddio))
		return dev_err_probe(dev, PTR_ERR(ts->vddio), "Failed to get VDDIO regulator\n");

retry_get_irq_gpio:
	/* Get the interrupt GPIO pin number */
	gpiod = devm_gpiod_get_optional(dev, GOODIX_GPIO_INT_NAME, GPIOD_IN);
	if (IS_ERR(gpiod))
		return dev_err_probe(dev, PTR_ERR(gpiod), "Failed to get %s GPIO\n",
				     GOODIX_GPIO_INT_NAME);

	if (!gpiod && has_acpi_companion(dev) && !added_acpi_mappings) {
		added_acpi_mappings = true;
		if (goodix_add_acpi_gpio_mappings(ts) == 0)
			goto retry_get_irq_gpio;
	}

	ts->gpiod_int = gpiod;

	/* Get the reset line GPIO pin number */
	gpiod = devm_gpiod_get_optional(dev, GOODIX_GPIO_RST_NAME, ts->gpiod_rst_flags);
	if (IS_ERR(gpiod))
		return dev_err_probe(dev, PTR_ERR(gpiod), "Failed to get %s GPIO\n",
				     GOODIX_GPIO_RST_NAME);

	ts->gpiod_rst = gpiod;

	switch (ts->irq_pin_access_method) {
	case IRQ_PIN_ACCESS_ACPI_GPIO:
		/*
		 * We end up here if goodix_add_acpi_gpio_mappings() has
		 * called devm_acpi_dev_add_driver_gpios() because the ACPI
		 * tables did not contain name to index mappings.
		 * Check that we successfully got both GPIOs after we've
		 * added our own acpi_gpio_mapping and if we did not get both
		 * GPIOs reset irq_pin_access_method to IRQ_PIN_ACCESS_NONE.
		 */
		if (!ts->gpiod_int || !ts->gpiod_rst)
			ts->irq_pin_access_method = IRQ_PIN_ACCESS_NONE;
		break;
	case IRQ_PIN_ACCESS_ACPI_METHOD:
		if (!ts->gpiod_rst)
			ts->irq_pin_access_method = IRQ_PIN_ACCESS_NONE;
		break;
	default:
		if (ts->gpiod_int && ts->gpiod_rst) {
			ts->reset_controller_at_probe = true;
			ts->load_cfg_from_disk = true;
			ts->irq_pin_access_method = IRQ_PIN_ACCESS_GPIO;
		}
	}

	return 0;
}

/**
 * goodix_read_config - Read the embedded configuration of the panel
 *
 * @ts: our goodix_ts_data pointer
 *
 * Must be called during probe
 */
static void goodix_read_config(struct goodix_ts_data *ts)
{
	int x_max, y_max;
	int error;

	/*
	 * On controllers where we need to upload the firmware
	 * (controllers without flash) ts->config already has the config
	 * at this point and the controller itself does not have it yet!
	 */
	if (!ts->firmware_name) {
		error = goodix_i2c_read(ts->client, ts->chip->config_addr,
					ts->config, ts->chip->config_len);
		if (error) {
			ts->int_trigger_type = GOODIX_INT_TRIGGER;
			ts->max_touch_num = GOODIX_MAX_CONTACTS;
			return;
		}
	}

	ts->int_trigger_type = ts->config[TRIGGER_LOC] & 0x03;
	ts->max_touch_num = ts->config[MAX_CONTACTS_LOC] & 0x0f;

	x_max = get_unaligned_le16(&ts->config[RESOLUTION_LOC]);
	y_max = get_unaligned_le16(&ts->config[RESOLUTION_LOC + 2]);
	if (x_max && y_max) {
		input_abs_set_max(ts->input_dev, ABS_MT_POSITION_X, x_max - 1);
		input_abs_set_max(ts->input_dev, ABS_MT_POSITION_Y, y_max - 1);
	}

	ts->chip->calc_config_checksum(ts);
}

/**
 * goodix_read_version - Read goodix touchscreen version
 *
 * @ts: our goodix_ts_data pointer
 */
static int goodix_read_version(struct goodix_ts_data *ts)
{
	int error;
	u8 buf[6];
	char id_str[GOODIX_ID_MAX_LEN + 1];

	error = goodix_i2c_read(ts->client, GOODIX_REG_ID, buf, sizeof(buf));
	if (error)
		return error;

	memcpy(id_str, buf, GOODIX_ID_MAX_LEN);
	id_str[GOODIX_ID_MAX_LEN] = 0;
	strscpy(ts->id, id_str, GOODIX_ID_MAX_LEN + 1);

	ts->version = get_unaligned_le16(&buf[4]);

	dev_info(&ts->client->dev, "ID %s, version: %04x\n", ts->id,
		 ts->version);

	return 0;
}

/**
 * goodix_i2c_test - I2C test function to check if the device answers.
 *
 * @client: the i2c client
 */
static int goodix_i2c_test(struct i2c_client *client)
{
	int retry = 0;
	int error;
	u8 test;

	while (retry++ < 2) {
		error = goodix_i2c_read(client, GOODIX_REG_ID, &test, 1);
		if (!error)
			return 0;

		msleep(20);
	}

	return error;
}

/**
 * goodix_configure_dev - Finish device initialization
 *
 * @ts: our goodix_ts_data pointer
 *
 * Must be called from probe to finish initialization of the device.
 * Contains the common initialization code for both devices that
 * declare gpio pins and devices that do not. It is either called
 * directly from probe or from request_firmware_wait callback.
 */
static int goodix_configure_dev(struct goodix_ts_data *ts)
{
	int error;
	int i;

	ts->int_trigger_type = GOODIX_INT_TRIGGER;
	ts->max_touch_num = GOODIX_MAX_CONTACTS;

	ts->input_dev = devm_input_allocate_device(&ts->client->dev);
	if (!ts->input_dev) {
		dev_err(&ts->client->dev, "Failed to allocate input device.");
		return -ENOMEM;
	}

	ts->input_dev->name = "Goodix Capacitive TouchScreen";
	ts->input_dev->phys = "input/ts";
	ts->input_dev->id.bustype = BUS_I2C;
	ts->input_dev->id.vendor = 0x0416;
	if (kstrtou16(ts->id, 10, &ts->input_dev->id.product))
		ts->input_dev->id.product = 0x1001;
	ts->input_dev->id.version = ts->version;

	ts->input_dev->keycode = ts->keymap;
	ts->input_dev->keycodesize = sizeof(ts->keymap[0]);
	ts->input_dev->keycodemax = GOODIX_MAX_KEYS;

	/* Capacitive Windows/Home button on some devices */
	for (i = 0; i < GOODIX_MAX_KEYS; ++i) {
		if (i == 0)
			ts->keymap[i] = KEY_LEFTMETA;
		else
			ts->keymap[i] = KEY_F1 + (i - 1);

		input_set_capability(ts->input_dev, EV_KEY, ts->keymap[i]);
	}

	input_set_capability(ts->input_dev, EV_ABS, ABS_MT_POSITION_X);
	input_set_capability(ts->input_dev, EV_ABS, ABS_MT_POSITION_Y);
	input_set_abs_params(ts->input_dev, ABS_MT_WIDTH_MAJOR, 0, 255, 0, 0);
	input_set_abs_params(ts->input_dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);

retry_read_config:
	/* Read configuration and apply touchscreen parameters */
	goodix_read_config(ts);

	/* Try overriding touchscreen parameters via device properties */
	touchscreen_parse_properties(ts->input_dev, true, &ts->prop);

	if (!ts->prop.max_x || !ts->prop.max_y || !ts->max_touch_num) {
		if (!ts->reset_controller_at_probe &&
		    ts->irq_pin_access_method != IRQ_PIN_ACCESS_NONE) {
			dev_info(&ts->client->dev, "Config not set, resetting controller\n");
			/* Retry after a controller reset */
			ts->reset_controller_at_probe = true;
			error = goodix_reset(ts);
			if (error)
				return error;
			goto retry_read_config;
		}
		dev_err(&ts->client->dev,
			"Invalid config (%d, %d, %d), using defaults\n",
			ts->prop.max_x, ts->prop.max_y, ts->max_touch_num);
		ts->prop.max_x = GOODIX_MAX_WIDTH - 1;
		ts->prop.max_y = GOODIX_MAX_HEIGHT - 1;
		ts->max_touch_num = GOODIX_MAX_CONTACTS;
		input_abs_set_max(ts->input_dev,
				  ABS_MT_POSITION_X, ts->prop.max_x);
		input_abs_set_max(ts->input_dev,
				  ABS_MT_POSITION_Y, ts->prop.max_y);
	}

	if (dmi_check_system(nine_bytes_report)) {
		ts->contact_size = 9;

		dev_dbg(&ts->client->dev,
			"Non-standard 9-bytes report format quirk\n");
	}

	if (dmi_check_system(inverted_x_screen)) {
		ts->prop.invert_x = true;
		dev_dbg(&ts->client->dev,
			"Applying 'inverted x screen' quirk\n");
	}

	error = input_mt_init_slots(ts->input_dev, ts->max_touch_num,
				    INPUT_MT_DIRECT | INPUT_MT_DROP_UNUSED);
	if (error) {
		dev_err(&ts->client->dev,
			"Failed to initialize MT slots: %d", error);
		return error;
	}

	input_set_drvdata(ts->input_dev, ts);

	if (!ts->client->irq) {
		error = input_setup_polling(ts->input_dev, goodix_ts_work_i2c_poll);
		if (error) {
			dev_err(&ts->client->dev,
				 "could not set up polling mode, %d\n", error);
			return error;
		}
		input_set_poll_interval(ts->input_dev, GOODIX_POLL_INTERVAL_MS);
	}

	error = input_register_device(ts->input_dev);
	if (error) {
		dev_err(&ts->client->dev,
			"Failed to register input device: %d", error);
		return error;
	}

	/*
	 * Create the input_pen device before goodix_request_irq() calls
	 * devm_request_threaded_irq() so that the devm framework frees
	 * it after disabling the irq.
	 * Unfortunately there is no way to detect if the touchscreen has pen
	 * support, so registering the dev is delayed till the first pen event.
	 */
	error = goodix_create_pen_input(ts);
	if (error)
		return error;

	ts->irq_flags = goodix_irq_flags[ts->int_trigger_type] | IRQF_ONESHOT;
	error = goodix_request_irq(ts);
	if (error) {
		dev_err(&ts->client->dev, "request IRQ failed: %d\n", error);
		return error;
	}

	return 0;
}

/**
 * goodix_config_cb - Callback to finish device init
 *
 * @cfg: firmware config
 * @ctx: our goodix_ts_data pointer
 *
 * request_firmware_wait callback that finishes
 * initialization of the device.
 */
static void goodix_config_cb(const struct firmware *cfg, void *ctx)
{
	struct goodix_ts_data *ts = ctx;
	int error;

	if (ts->firmware_name) {
		if (!cfg)
			goto err_release_cfg;

		error = goodix_check_cfg(ts, cfg->data, cfg->size);
		if (error)
			goto err_release_cfg;

		memcpy(ts->config, cfg->data, cfg->size);
	} else if (cfg) {
		/* send device configuration to the firmware */
		error = goodix_send_cfg(ts, cfg->data, cfg->size);
		if (error)
			goto err_release_cfg;
	}

	goodix_configure_dev(ts);

err_release_cfg:
	release_firmware(cfg);
	complete_all(&ts->firmware_loading_complete);
}

static void goodix_disable_regulators(void *arg)
{
	struct goodix_ts_data *ts = arg;

	regulator_disable(ts->vddio);
	regulator_disable(ts->avdd28);
}

static int goodix_ts_probe(struct i2c_client *client)
{
	struct goodix_ts_data *ts;
	const char *cfg_name;
	int error;

	dev_dbg(&client->dev, "I2C Address: 0x%02x\n", client->addr);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(&client->dev, "I2C check functionality failed.\n");
		return -ENXIO;
	}

	ts = devm_kzalloc(&client->dev, sizeof(*ts), GFP_KERNEL);
	if (!ts)
		return -ENOMEM;

	ts->client = client;
	i2c_set_clientdata(client, ts);
	init_completion(&ts->firmware_loading_complete);
	ts->contact_size = GOODIX_CONTACT_SIZE;

	error = goodix_get_gpio_config(ts);
	if (error)
		return error;

	/* power up the controller */
	error = regulator_enable(ts->avdd28);
	if (error) {
		dev_err(&client->dev,
			"Failed to enable AVDD28 regulator: %d\n",
			error);
		return error;
	}

	error = regulator_enable(ts->vddio);
	if (error) {
		dev_err(&client->dev,
			"Failed to enable VDDIO regulator: %d\n",
			error);
		regulator_disable(ts->avdd28);
		return error;
	}

	error = devm_add_action_or_reset(&client->dev,
					 goodix_disable_regulators, ts);
	if (error)
		return error;

reset:
	if (ts->reset_controller_at_probe) {
		/* reset the controller */
		error = goodix_reset(ts);
		if (error)
			return error;
	}

	error = goodix_i2c_test(client);
	if (error) {
		if (!ts->reset_controller_at_probe &&
		    ts->irq_pin_access_method != IRQ_PIN_ACCESS_NONE) {
			/* Retry after a controller reset */
			ts->reset_controller_at_probe = true;
			goto reset;
		}
		dev_err(&client->dev, "I2C communication failure: %d\n", error);
		return error;
	}

	error = goodix_firmware_check(ts);
	if (error)
		return error;

	error = goodix_read_version(ts);
	if (error)
		return error;

	ts->chip = goodix_get_chip_data(ts->id);

	if (ts->load_cfg_from_disk) {
		/* update device config */
		error = device_property_read_string(&client->dev,
						    "goodix,config-name",
						    &cfg_name);
		if (!error)
			snprintf(ts->cfg_name, sizeof(ts->cfg_name),
				 "goodix/%s", cfg_name);
		else
			snprintf(ts->cfg_name, sizeof(ts->cfg_name),
				 "goodix_%s_cfg.bin", ts->id);

		error = request_firmware_nowait(THIS_MODULE, true, ts->cfg_name,
						&client->dev, GFP_KERNEL, ts,
						goodix_config_cb);
		if (error) {
			dev_err(&client->dev,
				"Failed to invoke firmware loader: %d\n",
				error);
			return error;
		}

		return 0;
	} else {
		error = goodix_configure_dev(ts);
		if (error)
			return error;
	}

	return 0;
}

static void goodix_ts_remove(struct i2c_client *client)
{
	struct goodix_ts_data *ts = i2c_get_clientdata(client);

	if (ts->load_cfg_from_disk)
		wait_for_completion(&ts->firmware_loading_complete);
}

static int goodix_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct goodix_ts_data *ts = i2c_get_clientdata(client);
	int error;

	if (ts->load_cfg_from_disk)
		wait_for_completion(&ts->firmware_loading_complete);

	/* We need gpio pins to suspend/resume */
	if (ts->irq_pin_access_method == IRQ_PIN_ACCESS_NONE) {
		goodix_disable_irq(ts);
		return 0;
	}

	/* Free IRQ as IRQ pin is used as output in the suspend sequence */
	goodix_free_irq(ts);

	/* Save reference (calibration) info if necessary */
	goodix_save_bak_ref(ts);

	/* Output LOW on the INT pin for 5 ms */
	error = goodix_irq_direction_output(ts, 0);
	if (error) {
		goodix_request_irq(ts);
		return error;
	}

	usleep_range(5000, 6000);

	error = goodix_i2c_write_u8(ts->client, GOODIX_REG_COMMAND,
				    GOODIX_CMD_SCREEN_OFF);
	if (error) {
		goodix_irq_direction_input(ts);
		goodix_request_irq(ts);
		return -EAGAIN;
	}

	/*
	 * The datasheet specifies that the interval between sending screen-off
	 * command and wake-up should be longer than 58 ms. To avoid waking up
	 * sooner, delay 58ms here.
	 */
	msleep(58);
	return 0;
}

static int goodix_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct goodix_ts_data *ts = i2c_get_clientdata(client);
	u8 config_ver;
	int error;

	if (ts->irq_pin_access_method == IRQ_PIN_ACCESS_NONE) {
		goodix_enable_irq(ts);
		return 0;
	}

	/*
	 * Exit sleep mode by outputting HIGH level to INT pin
	 * for 2ms~5ms.
	 */
	error = goodix_irq_direction_output(ts, 1);
	if (error)
		return error;

	usleep_range(2000, 5000);

	error = goodix_int_sync(ts);
	if (error)
		return error;

	error = goodix_i2c_read(ts->client, ts->chip->config_addr,
				&config_ver, 1);
	if (!error && config_ver != ts->config[0])
		dev_info(dev, "Config version mismatch %d != %d, resetting controller\n",
			 config_ver, ts->config[0]);

	if (error != 0 || config_ver != ts->config[0]) {
		error = goodix_reset(ts);
		if (error)
			return error;

		error = goodix_send_cfg(ts, ts->config, ts->chip->config_len);
		if (error)
			return error;
	}

	error = goodix_request_irq(ts);
	if (error)
		return error;

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(goodix_pm_ops, goodix_suspend, goodix_resume);

static const struct i2c_device_id goodix_ts_id[] = {
	{ "GDIX1001:00" },
	{ }
};
MODULE_DEVICE_TABLE(i2c, goodix_ts_id);

#ifdef CONFIG_ACPI
static const struct acpi_device_id goodix_acpi_match[] = {
	{ "GDIX1001", 0 },
	{ "GDIX1002", 0 },
	{ "GDX9110", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, goodix_acpi_match);
#endif

#ifdef CONFIG_OF
static const struct of_device_id goodix_of_match[] = {
	{ .compatible = "goodix,gt1151" },
	{ .compatible = "goodix,gt1158" },
	{ .compatible = "goodix,gt5663" },
	{ .compatible = "goodix,gt5688" },
	{ .compatible = "goodix,gt911" },
	{ .compatible = "goodix,gt9110" },
	{ .compatible = "goodix,gt912" },
	{ .compatible = "goodix,gt9147" },
	{ .compatible = "goodix,gt917s" },
	{ .compatible = "goodix,gt927" },
	{ .compatible = "goodix,gt9271" },
	{ .compatible = "goodix,gt928" },
	{ .compatible = "goodix,gt9286" },
	{ .compatible = "goodix,gt967" },
	{ }
};
MODULE_DEVICE_TABLE(of, goodix_of_match);
#endif

static struct i2c_driver goodix_ts_driver = {
	.probe = goodix_ts_probe,
	.remove = goodix_ts_remove,
	.id_table = goodix_ts_id,
	.driver = {
		.name = "Goodix-TS",
		.acpi_match_table = ACPI_PTR(goodix_acpi_match),
		.of_match_table = of_match_ptr(goodix_of_match),
		.pm = pm_sleep_ptr(&goodix_pm_ops),
	},
};
module_i2c_driver(goodix_ts_driver);

MODULE_AUTHOR("Benjamin Tissoires <benjamin.tissoires@gmail.com>");
MODULE_AUTHOR("Bastien Nocera <hadess@hadess.net>");
MODULE_DESCRIPTION("Goodix touchscreen driver");
MODULE_LICENSE("GPL v2");
