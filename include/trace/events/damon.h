/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM damon

#if !defined(_TRACE_DAMON_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_DAMON_H

#include <linux/damon.h>
#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(damos_esz,

	TP_PROTO(unsigned int context_idx, unsigned int scheme_idx,
		unsigned long esz),

	TP_ARGS(context_idx, scheme_idx, esz),

	TP_STRUCT__entry(
		__field(unsigned int, context_idx)
		__field(unsigned int, scheme_idx)
		__field(unsigned long, esz)
	),

	TP_fast_assign(
		__entry->context_idx = context_idx;
		__entry->scheme_idx = scheme_idx;
		__entry->esz = esz;
	),

	TP_printk("ctx_idx=%u scheme_idx=%u esz=%lu",
			__entry->context_idx, __entry->scheme_idx,
			__entry->esz)
);

TRACE_EVENT_CONDITION(damos_before_apply,

	TP_PROTO(unsigned int context_idx, unsigned int scheme_idx,
		unsigned int target_idx, struct damon_region *r,
		unsigned int nr_regions, bool do_trace),

	TP_ARGS(context_idx, scheme_idx, target_idx, r, nr_regions, do_trace),

	TP_CONDITION(do_trace),

	TP_STRUCT__entry(
		__field(unsigned int, context_idx)
		__field(unsigned int, scheme_idx)
		__field(unsigned long, target_idx)
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned int, nr_accesses)
		__field(unsigned int, age)
		__field(unsigned int, nr_regions)
	),

	TP_fast_assign(
		__entry->context_idx = context_idx;
		__entry->scheme_idx = scheme_idx;
		__entry->target_idx = target_idx;
		__entry->start = r->ar.start;
		__entry->end = r->ar.end;
		__entry->nr_accesses = r->nr_accesses_bp / 10000;
		__entry->age = r->age;
		__entry->nr_regions = nr_regions;
	),

	TP_printk("ctx_idx=%u scheme_idx=%u target_idx=%lu nr_regions=%u %lu-%lu: %u %u",
			__entry->context_idx, __entry->scheme_idx,
			__entry->target_idx, __entry->nr_regions,
			__entry->start, __entry->end,
			__entry->nr_accesses, __entry->age)
);

TRACE_EVENT(damon_monitor_intervals_tune,

	TP_PROTO(unsigned long sample_us),

	TP_ARGS(sample_us),

	TP_STRUCT__entry(
		__field(unsigned long, sample_us)
	),

	TP_fast_assign(
		__entry->sample_us = sample_us;
	),

	TP_printk("sample_us=%lu", __entry->sample_us)
);

TRACE_EVENT(damon_aggregated,

	TP_PROTO(unsigned int target_id, struct damon_region *r,
		unsigned int nr_regions),

	TP_ARGS(target_id, r, nr_regions),

	TP_STRUCT__entry(
		__field(unsigned long, target_id)
		__field(unsigned int, nr_regions)
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned int, nr_accesses)
		__field(unsigned int, age)
	),

	TP_fast_assign(
		__entry->target_id = target_id;
		__entry->nr_regions = nr_regions;
		__entry->start = r->ar.start;
		__entry->end = r->ar.end;
		__entry->nr_accesses = r->nr_accesses;
		__entry->age = r->age;
	),

	TP_printk("target_id=%lu nr_regions=%u %lu-%lu: %u %u",
			__entry->target_id, __entry->nr_regions,
			__entry->start, __entry->end,
			__entry->nr_accesses, __entry->age)
);

#endif /* _TRACE_DAMON_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
