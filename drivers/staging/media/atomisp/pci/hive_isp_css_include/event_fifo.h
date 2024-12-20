/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Support for Intel Camera Imaging ISP subsystem.
 * Copyright (c) 2015, Intel Corporation.
 */

#ifndef __EVENT_FIFO_H
#define __EVENT_FIFO_H

/*
 * This file is included on every cell {SP,ISP,host} and on every system
 * that uses the IRQ device. It defines the API to DLI bridge
 *
 * System and cell specific interfaces and inline code are included
 * conditionally through Makefile path settings.
 *
 *  - .        system and cell agnostic interfaces, constants and identifiers
 *	- public:  system agnostic, cell specific interfaces
 *	- private: system dependent, cell specific interfaces & inline implementations
 *	- global:  system specific constants and identifiers
 *	- local:   system and cell specific constants and identifiers
 */

#include "system_local.h"
#include "event_fifo_local.h"

#ifndef __INLINE_EVENT__
#define STORAGE_CLASS_EVENT_H extern
#define STORAGE_CLASS_EVENT_C
#include "event_fifo_public.h"
#else  /* __INLINE_EVENT__ */
#define STORAGE_CLASS_EVENT_H static inline
#define STORAGE_CLASS_EVENT_C static inline
#include "event_fifo_private.h"
#endif /* __INLINE_EVENT__ */

#endif /* __EVENT_FIFO_H */
