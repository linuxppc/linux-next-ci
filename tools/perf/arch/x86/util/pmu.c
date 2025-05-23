// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/stddef.h>
#include <linux/perf_event.h>
#include <linux/zalloc.h>
#include <api/fs/fs.h>
#include <errno.h>

#include "../../../util/intel-pt.h"
#include "../../../util/intel-bts.h"
#include "../../../util/pmu.h"
#include "../../../util/fncache.h"
#include "../../../util/pmus.h"
#include "mem-events.h"
#include "util/env.h"

void perf_pmu__arch_init(struct perf_pmu *pmu)
{
	struct perf_pmu_caps *ldlat_cap;

#ifdef HAVE_AUXTRACE_SUPPORT
	if (!strcmp(pmu->name, INTEL_PT_PMU_NAME)) {
		pmu->auxtrace = true;
		pmu->selectable = true;
		pmu->perf_event_attr_init_default = intel_pt_pmu_default_config;
	}
	if (!strcmp(pmu->name, INTEL_BTS_PMU_NAME)) {
		pmu->auxtrace = true;
		pmu->selectable = true;
	}
#endif

	if (x86__is_amd_cpu()) {
		if (strcmp(pmu->name, "ibs_op"))
			return;

		pmu->mem_events = perf_mem_events_amd;

		if (!perf_pmu__caps_parse(pmu))
			return;

		ldlat_cap = perf_pmu__get_cap(pmu, "ldlat");
		if (!ldlat_cap || strcmp(ldlat_cap->value, "1"))
			return;

		perf_mem_events__loads_ldlat = 0;
		pmu->mem_events = perf_mem_events_amd_ldlat;
	} else if (pmu->is_core) {
		if (perf_pmu__have_event(pmu, "mem-loads-aux"))
			pmu->mem_events = perf_mem_events_intel_aux;
		else
			pmu->mem_events = perf_mem_events_intel;
	}
}
