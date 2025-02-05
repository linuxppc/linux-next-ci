/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arm v8 Self-Hosted trace support.
 *
 * Copyright (C) 2021 ARM Ltd.
 */

#ifndef __CORESIGHT_SELF_HOSTED_TRACE_H
#define __CORESIGHT_SELF_HOSTED_TRACE_H

#include <asm/sysreg.h>

static inline u64 read_trfcr(void)
{
	return read_sysreg_s(SYS_TRFCR_EL1);
}

static inline void write_trfcr(u64 val)
{
	write_sysreg_s(val, SYS_TRFCR_EL1);
	isb();
}

#endif /*  __CORESIGHT_SELF_HOSTED_TRACE_H */
