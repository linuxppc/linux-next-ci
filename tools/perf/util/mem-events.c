// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <api/fs/fs.h>
#include <linux/kernel.h>
#include "cpumap.h"
#include "map_symbol.h"
#include "mem-events.h"
#include "mem-info.h"
#include "debug.h"
#include "evsel.h"
#include "symbol.h"
#include "pmu.h"
#include "pmus.h"

unsigned int perf_mem_events__loads_ldlat = 30;

#define E(t, n, s, l, a) { .tag = t, .name = n, .event_name = s, .ldlat = l, .aux_event = a }

struct perf_mem_event perf_mem_events[PERF_MEM_EVENTS__MAX] = {
	E("ldlat-loads",	"%s/mem-loads,ldlat=%u/P",	"mem-loads",	true,	0),
	E("ldlat-stores",	"%s/mem-stores/P",		"mem-stores",	false,	0),
	E(NULL,			NULL,				NULL,		false,	0),
};
#undef E

bool perf_mem_record[PERF_MEM_EVENTS__MAX] = { 0 };

struct perf_mem_event *perf_pmu__mem_events_ptr(struct perf_pmu *pmu, int i)
{
	if (i >= PERF_MEM_EVENTS__MAX || !pmu)
		return NULL;

	return &pmu->mem_events[i];
}

static struct perf_pmu *perf_pmus__scan_mem(struct perf_pmu *pmu)
{
	while ((pmu = perf_pmus__scan(pmu)) != NULL) {
		if (pmu->mem_events)
			return pmu;
	}
	return NULL;
}

struct perf_pmu *perf_mem_events_find_pmu(void)
{
	/*
	 * The current perf mem doesn't support per-PMU configuration.
	 * The exact same configuration is applied to all the
	 * mem_events supported PMUs.
	 * Return the first mem_events supported PMU.
	 *
	 * Notes: The only case which may support multiple mem_events
	 * supported PMUs is Intel hybrid. The exact same mem_events
	 * is shared among the PMUs. Only configure the first PMU
	 * is good enough as well.
	 */
	return perf_pmus__scan_mem(NULL);
}

/**
 * perf_pmu__mem_events_num_mem_pmus - Get the number of mem PMUs since the given pmu
 * @pmu: Start pmu. If it's NULL, search the entire PMU list.
 */
int perf_pmu__mem_events_num_mem_pmus(struct perf_pmu *pmu)
{
	int num = 0;

	while ((pmu = perf_pmus__scan_mem(pmu)) != NULL)
		num++;

	return num;
}

static const char *perf_pmu__mem_events_name(struct perf_pmu *pmu, int i,
					     char *buf, size_t buf_size)
{
	struct perf_mem_event *e;

	if (i >= PERF_MEM_EVENTS__MAX || !pmu)
		return NULL;

	e = &pmu->mem_events[i];
	if (!e || !e->name)
		return NULL;

	if (i == PERF_MEM_EVENTS__LOAD || i == PERF_MEM_EVENTS__LOAD_STORE) {
		if (e->ldlat) {
			if (!e->aux_event) {
				/* ARM and Most of Intel */
				scnprintf(buf, buf_size,
					  e->name, pmu->name,
					  perf_mem_events__loads_ldlat);
			} else {
				/* Intel with mem-loads-aux event */
				scnprintf(buf, buf_size,
					  e->name, pmu->name, pmu->name,
					  perf_mem_events__loads_ldlat);
			}
		} else {
			if (!e->aux_event) {
				/* AMD and POWER */
				scnprintf(buf, buf_size,
					  e->name, pmu->name);
			} else {
				return NULL;
			}
		}
		return buf;
	}

	if (i == PERF_MEM_EVENTS__STORE) {
		scnprintf(buf, buf_size,
			  e->name, pmu->name);
		return buf;
	}

	return NULL;
}

bool is_mem_loads_aux_event(struct evsel *leader)
{
	struct perf_pmu *pmu = leader->pmu;
	struct perf_mem_event *e;

	if (!pmu || !pmu->mem_events)
		return false;

	e = &pmu->mem_events[PERF_MEM_EVENTS__LOAD];
	if (!e->aux_event)
		return false;

	return leader->core.attr.config == e->aux_event;
}

int perf_pmu__mem_events_parse(struct perf_pmu *pmu, const char *str)
{
	char *tok, *saveptr = NULL;
	bool found = false;
	char *buf;
	int j;

	/* We need buffer that we know we can write to. */
	buf = malloc(strlen(str) + 1);
	if (!buf)
		return -ENOMEM;

	strcpy(buf, str);

	tok = strtok_r((char *)buf, ",", &saveptr);

	while (tok) {
		for (j = 0; j < PERF_MEM_EVENTS__MAX; j++) {
			struct perf_mem_event *e = perf_pmu__mem_events_ptr(pmu, j);

			if (!e->tag)
				continue;

			if (strstr(e->tag, tok))
				perf_mem_record[j] = found = true;
		}

		tok = strtok_r(NULL, ",", &saveptr);
	}

	free(buf);

	if (found)
		return 0;

	pr_err("failed: event '%s' not found, use '-e list' to get list of available events\n", str);
	return -1;
}

static bool perf_pmu__mem_events_supported(const char *mnt, struct perf_pmu *pmu,
				      struct perf_mem_event *e)
{
	char path[PATH_MAX];
	struct stat st;

	if (!e->event_name)
		return true;

	scnprintf(path, PATH_MAX, "%s/bus/event_source/devices/%s/events/%s", mnt, pmu->name, e->event_name);

	return !stat(path, &st);
}

static int __perf_pmu__mem_events_init(struct perf_pmu *pmu)
{
	const char *mnt = sysfs__mount();
	bool found = false;
	int j;

	if (!mnt)
		return -ENOENT;

	for (j = 0; j < PERF_MEM_EVENTS__MAX; j++) {
		struct perf_mem_event *e = perf_pmu__mem_events_ptr(pmu, j);

		/*
		 * If the event entry isn't valid, skip initialization
		 * and "e->supported" will keep false.
		 */
		if (!e->tag)
			continue;

		e->supported |= perf_pmu__mem_events_supported(mnt, pmu, e);
		if (e->supported)
			found = true;
	}

	return found ? 0 : -ENOENT;
}

int perf_pmu__mem_events_init(void)
{
	struct perf_pmu *pmu = NULL;

	while ((pmu = perf_pmus__scan_mem(pmu)) != NULL) {
		if (__perf_pmu__mem_events_init(pmu))
			return -ENOENT;
	}

	return 0;
}

void perf_pmu__mem_events_list(struct perf_pmu *pmu)
{
	int j;

	for (j = 0; j < PERF_MEM_EVENTS__MAX; j++) {
		char buf[128];
		struct perf_mem_event *e = perf_pmu__mem_events_ptr(pmu, j);

		fprintf(stderr, "%-*s%-*s%s",
			e->tag ? 13 : 0,
			e->tag ? : "",
			e->tag && verbose > 0 ? 25 : 0,
			e->tag && verbose > 0
			? perf_pmu__mem_events_name(pmu, j, buf, sizeof(buf))
			: "",
			e->supported ? ": available\n" : "");
	}
}

int perf_mem_events__record_args(const char **rec_argv, int *argv_nr, char **event_name_storage_out)
{
	const char *mnt = sysfs__mount();
	struct perf_pmu *pmu = NULL;
	int i = *argv_nr;
	struct perf_cpu_map *cpu_map = NULL;
	size_t event_name_storage_size =
		perf_pmu__mem_events_num_mem_pmus(NULL) * PERF_MEM_EVENTS__MAX * 128;
	size_t event_name_storage_remaining = event_name_storage_size;
	char *event_name_storage = malloc(event_name_storage_size);
	char *event_name_storage_ptr = event_name_storage;

	if (!event_name_storage)
		return -ENOMEM;

	*event_name_storage_out = NULL;
	while ((pmu = perf_pmus__scan_mem(pmu)) != NULL) {
		for (int j = 0; j < PERF_MEM_EVENTS__MAX; j++) {
			const char *s;
			struct perf_mem_event *e = perf_pmu__mem_events_ptr(pmu, j);
			int ret;

			if (!perf_mem_record[j])
				continue;

			if (!e->supported) {
				char buf[128];

				pr_err("failed: event '%s' not supported\n",
					perf_pmu__mem_events_name(pmu, j, buf, sizeof(buf)));
				free(event_name_storage);
				return -1;
			}

			s = perf_pmu__mem_events_name(pmu, j, event_name_storage_ptr,
						      event_name_storage_remaining);
			if (!s || !perf_pmu__mem_events_supported(mnt, pmu, e))
				continue;

			rec_argv[i++] = "-e";
			rec_argv[i++] = event_name_storage_ptr;
			event_name_storage_remaining -= strlen(event_name_storage_ptr) + 1;
			event_name_storage_ptr += strlen(event_name_storage_ptr) + 1;

			ret = perf_cpu_map__merge(&cpu_map, pmu->cpus);
			if (ret < 0) {
				free(event_name_storage);
				return ret;
			}
		}
	}

	if (cpu_map) {
		if (!perf_cpu_map__equal(cpu_map, cpu_map__online())) {
			char buf[200];

			cpu_map__snprint(cpu_map, buf, sizeof(buf));
			pr_warning("Memory events are enabled on a subset of CPUs: %s\n", buf);
		}
		perf_cpu_map__put(cpu_map);
	}

	*argv_nr = i;
	*event_name_storage_out = event_name_storage;
	return 0;
}

static const char * const tlb_access[] = {
	"N/A",
	"HIT",
	"MISS",
	"L1",
	"L2",
	"Walker",
	"Fault",
};

int perf_mem__tlb_scnprintf(char *out, size_t sz, const struct mem_info *mem_info)
{
	size_t l = 0, i;
	u64 m = PERF_MEM_TLB_NA;
	u64 hit, miss;

	sz -= 1; /* -1 for null termination */
	out[0] = '\0';

	if (mem_info)
		m = mem_info__const_data_src(mem_info)->mem_dtlb;

	hit = m & PERF_MEM_TLB_HIT;
	miss = m & PERF_MEM_TLB_MISS;

	/* already taken care of */
	m &= ~(PERF_MEM_TLB_HIT|PERF_MEM_TLB_MISS);

	for (i = 0; m && i < ARRAY_SIZE(tlb_access); i++, m >>= 1) {
		if (!(m & 0x1))
			continue;
		if (l) {
			strcat(out, " or ");
			l += 4;
		}
		l += scnprintf(out + l, sz - l, tlb_access[i]);
	}
	if (*out == '\0')
		l += scnprintf(out, sz - l, "N/A");
	if (hit)
		l += scnprintf(out + l, sz - l, " hit");
	if (miss)
		l += scnprintf(out + l, sz - l, " miss");

	return l;
}

static const char * const mem_lvl[] = {
	"N/A",
	"HIT",
	"MISS",
	"L1",
	"LFB/MAB",
	"L2",
	"L3",
	"Local RAM",
	"Remote RAM (1 hop)",
	"Remote RAM (2 hops)",
	"Remote Cache (1 hop)",
	"Remote Cache (2 hops)",
	"I/O",
	"Uncached",
};

static const char * const mem_lvlnum[] = {
	[PERF_MEM_LVLNUM_L1] = "L1",
	[PERF_MEM_LVLNUM_L2] = "L2",
	[PERF_MEM_LVLNUM_L3] = "L3",
	[PERF_MEM_LVLNUM_L4] = "L4",
	[PERF_MEM_LVLNUM_L2_MHB] = "L2 MHB",
	[PERF_MEM_LVLNUM_MSC] = "Memory-side Cache",
	[PERF_MEM_LVLNUM_UNC] = "Uncached",
	[PERF_MEM_LVLNUM_CXL] = "CXL",
	[PERF_MEM_LVLNUM_IO] = "I/O",
	[PERF_MEM_LVLNUM_ANY_CACHE] = "Any cache",
	[PERF_MEM_LVLNUM_LFB] = "LFB/MAB",
	[PERF_MEM_LVLNUM_RAM] = "RAM",
	[PERF_MEM_LVLNUM_PMEM] = "PMEM",
	[PERF_MEM_LVLNUM_NA] = "N/A",
};

static const char * const mem_hops[] = {
	"N/A",
	/*
	 * While printing, 'Remote' will be added to represent
	 * 'Remote core, same node' accesses as remote field need
	 * to be set with mem_hops field.
	 */
	"core, same node",
	"node, same socket",
	"socket, same board",
	"board",
};

static int perf_mem__op_scnprintf(char *out, size_t sz, const struct mem_info *mem_info)
{
	u64 op = PERF_MEM_LOCK_NA;
	int l;

	if (mem_info)
		op = mem_info__const_data_src(mem_info)->mem_op;

	if (op & PERF_MEM_OP_NA)
		l = scnprintf(out, sz, "N/A");
	else if (op & PERF_MEM_OP_LOAD)
		l = scnprintf(out, sz, "LOAD");
	else if (op & PERF_MEM_OP_STORE)
		l = scnprintf(out, sz, "STORE");
	else if (op & PERF_MEM_OP_PFETCH)
		l = scnprintf(out, sz, "PFETCH");
	else if (op & PERF_MEM_OP_EXEC)
		l = scnprintf(out, sz, "EXEC");
	else
		l = scnprintf(out, sz, "No");

	return l;
}

int perf_mem__lvl_scnprintf(char *out, size_t sz, const struct mem_info *mem_info)
{
	union perf_mem_data_src data_src;
	int printed = 0;
	size_t l = 0;
	size_t i;
	int lvl;
	char hit_miss[5] = {0};

	sz -= 1; /* -1 for null termination */
	out[0] = '\0';

	if (!mem_info)
		goto na;

	data_src = *mem_info__const_data_src(mem_info);

	if (data_src.mem_lvl & PERF_MEM_LVL_HIT)
		memcpy(hit_miss, "hit", 3);
	else if (data_src.mem_lvl & PERF_MEM_LVL_MISS)
		memcpy(hit_miss, "miss", 4);

	lvl = data_src.mem_lvl_num;
	if (lvl && lvl != PERF_MEM_LVLNUM_NA) {
		if (data_src.mem_remote) {
			strcat(out, "Remote ");
			l += 7;
		}

		if (data_src.mem_hops)
			l += scnprintf(out + l, sz - l, "%s ", mem_hops[data_src.mem_hops]);

		if (mem_lvlnum[lvl])
			l += scnprintf(out + l, sz - l, mem_lvlnum[lvl]);
		else
			l += scnprintf(out + l, sz - l, "Unknown level %d", lvl);

		l += scnprintf(out + l, sz - l, " %s", hit_miss);
		return l;
	}

	lvl = data_src.mem_lvl;
	if (!lvl)
		goto na;

	lvl &= ~(PERF_MEM_LVL_NA | PERF_MEM_LVL_HIT | PERF_MEM_LVL_MISS);
	if (!lvl)
		goto na;

	for (i = 0; lvl && i < ARRAY_SIZE(mem_lvl); i++, lvl >>= 1) {
		if (!(lvl & 0x1))
			continue;
		if (printed++) {
			strcat(out, " or ");
			l += 4;
		}
		l += scnprintf(out + l, sz - l, mem_lvl[i]);
	}

	if (printed) {
		l += scnprintf(out + l, sz - l, " %s", hit_miss);
		return l;
	}

na:
	strcat(out, "N/A");
	return 3;
}

static const char * const snoop_access[] = {
	"N/A",
	"None",
	"Hit",
	"Miss",
	"HitM",
};

static const char * const snoopx_access[] = {
	"Fwd",
	"Peer",
};

int perf_mem__snp_scnprintf(char *out, size_t sz, const struct mem_info *mem_info)
{
	size_t i, l = 0;
	u64 m = PERF_MEM_SNOOP_NA;

	sz -= 1; /* -1 for null termination */
	out[0] = '\0';

	if (mem_info)
		m = mem_info__const_data_src(mem_info)->mem_snoop;

	for (i = 0; m && i < ARRAY_SIZE(snoop_access); i++, m >>= 1) {
		if (!(m & 0x1))
			continue;
		if (l) {
			strcat(out, " or ");
			l += 4;
		}
		l += scnprintf(out + l, sz - l, snoop_access[i]);
	}

	m = 0;
	if (mem_info)
		m = mem_info__const_data_src(mem_info)->mem_snoopx;

	for (i = 0; m && i < ARRAY_SIZE(snoopx_access); i++, m >>= 1) {
		if (!(m & 0x1))
			continue;

		if (l) {
			strcat(out, " or ");
			l += 4;
		}
		l += scnprintf(out + l, sz - l, snoopx_access[i]);
	}

	if (*out == '\0')
		l += scnprintf(out, sz - l, "N/A");

	return l;
}

int perf_mem__lck_scnprintf(char *out, size_t sz, const struct mem_info *mem_info)
{
	u64 mask = PERF_MEM_LOCK_NA;
	int l;

	if (mem_info)
		mask = mem_info__const_data_src(mem_info)->mem_lock;

	if (mask & PERF_MEM_LOCK_NA)
		l = scnprintf(out, sz, "N/A");
	else if (mask & PERF_MEM_LOCK_LOCKED)
		l = scnprintf(out, sz, "Yes");
	else
		l = scnprintf(out, sz, "No");

	return l;
}

int perf_mem__blk_scnprintf(char *out, size_t sz, const struct mem_info *mem_info)
{
	size_t l = 0;
	u64 mask = PERF_MEM_BLK_NA;

	sz -= 1; /* -1 for null termination */
	out[0] = '\0';

	if (mem_info)
		mask = mem_info__const_data_src(mem_info)->mem_blk;

	if (!mask || (mask & PERF_MEM_BLK_NA)) {
		l += scnprintf(out + l, sz - l, " N/A");
		return l;
	}
	if (mask & PERF_MEM_BLK_DATA)
		l += scnprintf(out + l, sz - l, " Data");
	if (mask & PERF_MEM_BLK_ADDR)
		l += scnprintf(out + l, sz - l, " Addr");

	return l;
}

int perf_script__meminfo_scnprintf(char *out, size_t sz, const struct mem_info *mem_info)
{
	int i = 0;

	i += scnprintf(out, sz, "|OP ");
	i += perf_mem__op_scnprintf(out + i, sz - i, mem_info);
	i += scnprintf(out + i, sz - i, "|LVL ");
	i += perf_mem__lvl_scnprintf(out + i, sz, mem_info);
	i += scnprintf(out + i, sz - i, "|SNP ");
	i += perf_mem__snp_scnprintf(out + i, sz - i, mem_info);
	i += scnprintf(out + i, sz - i, "|TLB ");
	i += perf_mem__tlb_scnprintf(out + i, sz - i, mem_info);
	i += scnprintf(out + i, sz - i, "|LCK ");
	i += perf_mem__lck_scnprintf(out + i, sz - i, mem_info);
	i += scnprintf(out + i, sz - i, "|BLK ");
	i += perf_mem__blk_scnprintf(out + i, sz - i, mem_info);

	return i;
}

int c2c_decode_stats(struct c2c_stats *stats, struct mem_info *mi)
{
	union perf_mem_data_src *data_src = mem_info__data_src(mi);
	u64 daddr  = mem_info__daddr(mi)->addr;
	u64 op     = data_src->mem_op;
	u64 lvl    = data_src->mem_lvl;
	u64 snoop  = data_src->mem_snoop;
	u64 snoopx = data_src->mem_snoopx;
	u64 lock   = data_src->mem_lock;
	u64 blk    = data_src->mem_blk;
	/*
	 * Skylake might report unknown remote level via this
	 * bit, consider it when evaluating remote HITMs.
	 *
	 * Incase of power, remote field can also be used to denote cache
	 * accesses from the another core of same node. Hence, setting
	 * mrem only when HOPS is zero along with set remote field.
	 */
	bool mrem  = (data_src->mem_remote && !data_src->mem_hops);
	int err = 0;

#define HITM_INC(__f)		\
do {				\
	stats->__f++;		\
	stats->tot_hitm++;	\
} while (0)

#define PEER_INC(__f)		\
do {				\
	stats->__f++;		\
	stats->tot_peer++;	\
} while (0)

#define P(a, b) PERF_MEM_##a##_##b

	stats->nr_entries++;

	if (lock & P(LOCK, LOCKED)) stats->locks++;

	if (blk & P(BLK, DATA)) stats->blk_data++;
	if (blk & P(BLK, ADDR)) stats->blk_addr++;

	if (op & P(OP, LOAD)) {
		/* load */
		stats->load++;

		if (!daddr) {
			stats->ld_noadrs++;
			return -1;
		}

		if (lvl & P(LVL, HIT)) {
			if (lvl & P(LVL, UNC)) stats->ld_uncache++;
			if (lvl & P(LVL, IO))  stats->ld_io++;
			if (lvl & P(LVL, LFB)) stats->ld_fbhit++;
			if (lvl & P(LVL, L1 )) stats->ld_l1hit++;
			if (lvl & P(LVL, L2)) {
				if (snoop & P(SNOOP, HITM))
					HITM_INC(lcl_hitm);
				else
					stats->ld_l2hit++;

				if (snoopx & P(SNOOPX, PEER))
					PEER_INC(lcl_peer);
			}
			if (lvl & P(LVL, L3 )) {
				if (snoop & P(SNOOP, HITM))
					HITM_INC(lcl_hitm);
				else
					stats->ld_llchit++;

				if (snoopx & P(SNOOPX, PEER))
					PEER_INC(lcl_peer);
			}

			if (lvl & P(LVL, LOC_RAM)) {
				stats->lcl_dram++;
				if (snoop & P(SNOOP, HIT))
					stats->ld_shared++;
				else
					stats->ld_excl++;
			}

			if ((lvl & P(LVL, REM_RAM1)) ||
			    (lvl & P(LVL, REM_RAM2)) ||
			     mrem) {
				stats->rmt_dram++;
				if (snoop & P(SNOOP, HIT))
					stats->ld_shared++;
				else
					stats->ld_excl++;
			}
		}

		if ((lvl & P(LVL, REM_CCE1)) ||
		    (lvl & P(LVL, REM_CCE2)) ||
		     mrem) {
			if (snoop & P(SNOOP, HIT)) {
				stats->rmt_hit++;
			} else if (snoop & P(SNOOP, HITM)) {
				HITM_INC(rmt_hitm);
			} else if (snoopx & P(SNOOPX, PEER)) {
				stats->rmt_hit++;
				PEER_INC(rmt_peer);
			}
		}

		if ((lvl & P(LVL, MISS)))
			stats->ld_miss++;

	} else if (op & P(OP, STORE)) {
		/* store */
		stats->store++;

		if (!daddr) {
			stats->st_noadrs++;
			return -1;
		}

		if (lvl & P(LVL, HIT)) {
			if (lvl & P(LVL, UNC)) stats->st_uncache++;
			if (lvl & P(LVL, L1 )) stats->st_l1hit++;
		}
		if (lvl & P(LVL, MISS))
			if (lvl & P(LVL, L1)) stats->st_l1miss++;
		if (lvl & P(LVL, NA))
			stats->st_na++;
	} else {
		/* unparsable data_src? */
		stats->noparse++;
		return -1;
	}

	if (!mem_info__daddr(mi)->ms.map || !mem_info__iaddr(mi)->ms.map) {
		stats->nomap++;
		return -1;
	}

#undef P
#undef HITM_INC
	return err;
}

void c2c_add_stats(struct c2c_stats *stats, struct c2c_stats *add)
{
	stats->nr_entries	+= add->nr_entries;

	stats->locks		+= add->locks;
	stats->store		+= add->store;
	stats->st_uncache	+= add->st_uncache;
	stats->st_noadrs	+= add->st_noadrs;
	stats->st_l1hit		+= add->st_l1hit;
	stats->st_l1miss	+= add->st_l1miss;
	stats->st_na		+= add->st_na;
	stats->load		+= add->load;
	stats->ld_excl		+= add->ld_excl;
	stats->ld_shared	+= add->ld_shared;
	stats->ld_uncache	+= add->ld_uncache;
	stats->ld_io		+= add->ld_io;
	stats->ld_miss		+= add->ld_miss;
	stats->ld_noadrs	+= add->ld_noadrs;
	stats->ld_fbhit		+= add->ld_fbhit;
	stats->ld_l1hit		+= add->ld_l1hit;
	stats->ld_l2hit		+= add->ld_l2hit;
	stats->ld_llchit	+= add->ld_llchit;
	stats->lcl_hitm		+= add->lcl_hitm;
	stats->rmt_hitm		+= add->rmt_hitm;
	stats->tot_hitm		+= add->tot_hitm;
	stats->lcl_peer		+= add->lcl_peer;
	stats->rmt_peer		+= add->rmt_peer;
	stats->tot_peer		+= add->tot_peer;
	stats->rmt_hit		+= add->rmt_hit;
	stats->lcl_dram		+= add->lcl_dram;
	stats->rmt_dram		+= add->rmt_dram;
	stats->blk_data		+= add->blk_data;
	stats->blk_addr		+= add->blk_addr;
	stats->nomap		+= add->nomap;
	stats->noparse		+= add->noparse;
}

/*
 * It returns an index in hist_entry->mem_stat array for the given val which
 * represents a data-src based on the mem_stat_type.
 */
int mem_stat_index(const enum mem_stat_type mst, const u64 val)
{
	union perf_mem_data_src src = {
		.val = val,
	};

	switch (mst) {
	case PERF_MEM_STAT_OP:
		switch (src.mem_op) {
		case PERF_MEM_OP_LOAD:
			return MEM_STAT_OP_LOAD;
		case PERF_MEM_OP_STORE:
			return MEM_STAT_OP_STORE;
		case PERF_MEM_OP_LOAD | PERF_MEM_OP_STORE:
			return MEM_STAT_OP_LDST;
		default:
			if (src.mem_op & PERF_MEM_OP_PFETCH)
				return MEM_STAT_OP_PFETCH;
			if (src.mem_op & PERF_MEM_OP_EXEC)
				return MEM_STAT_OP_EXEC;
			return MEM_STAT_OP_OTHER;
		}
	case PERF_MEM_STAT_CACHE:
		switch (src.mem_lvl_num) {
		case PERF_MEM_LVLNUM_L1:
			return MEM_STAT_CACHE_L1;
		case PERF_MEM_LVLNUM_L2:
			return MEM_STAT_CACHE_L2;
		case PERF_MEM_LVLNUM_L3:
			return MEM_STAT_CACHE_L3;
		case PERF_MEM_LVLNUM_L4:
			return MEM_STAT_CACHE_L4;
		case PERF_MEM_LVLNUM_LFB:
			return MEM_STAT_CACHE_L1_BUF;
		case PERF_MEM_LVLNUM_L2_MHB:
			return MEM_STAT_CACHE_L2_BUF;
		default:
			return MEM_STAT_CACHE_OTHER;
		}
	case PERF_MEM_STAT_MEMORY:
		switch (src.mem_lvl_num) {
		case PERF_MEM_LVLNUM_MSC:
			return MEM_STAT_MEMORY_MSC;
		case PERF_MEM_LVLNUM_RAM:
			return MEM_STAT_MEMORY_RAM;
		case PERF_MEM_LVLNUM_UNC:
			return MEM_STAT_MEMORY_UNC;
		case PERF_MEM_LVLNUM_CXL:
			return MEM_STAT_MEMORY_CXL;
		case PERF_MEM_LVLNUM_IO:
			return MEM_STAT_MEMORY_IO;
		case PERF_MEM_LVLNUM_PMEM:
			return MEM_STAT_MEMORY_PMEM;
		default:
			return MEM_STAT_MEMORY_OTHER;
		}
	case PERF_MEM_STAT_SNOOP:
		switch (src.mem_snoop) {
		case PERF_MEM_SNOOP_HIT:
			return MEM_STAT_SNOOP_HIT;
		case PERF_MEM_SNOOP_HITM:
			return MEM_STAT_SNOOP_HITM;
		case PERF_MEM_SNOOP_MISS:
			return MEM_STAT_SNOOP_MISS;
		default:
			return MEM_STAT_SNOOP_OTHER;
		}
	case PERF_MEM_STAT_DTLB:
		switch (src.mem_dtlb) {
		case PERF_MEM_TLB_L1 | PERF_MEM_TLB_HIT:
			return MEM_STAT_DTLB_L1_HIT;
		case PERF_MEM_TLB_L2 | PERF_MEM_TLB_HIT:
			return MEM_STAT_DTLB_L2_HIT;
		case PERF_MEM_TLB_L1 | PERF_MEM_TLB_L2 | PERF_MEM_TLB_HIT:
			return MEM_STAT_DTLB_ANY_HIT;
		default:
			if (src.mem_dtlb & PERF_MEM_TLB_MISS)
				return MEM_STAT_DTLB_MISS;
			return MEM_STAT_DTLB_OTHER;
		}
	default:
		break;
	}
	return -1;
}

/* To align output, returned string should be shorter than MEM_STAT_PRINT_LEN */
const char *mem_stat_name(const enum mem_stat_type mst, const int idx)
{
	switch (mst) {
	case PERF_MEM_STAT_OP:
		switch (idx) {
		case MEM_STAT_OP_LOAD:
			return "Load";
		case MEM_STAT_OP_STORE:
			return "Store";
		case MEM_STAT_OP_LDST:
			return "Ld+St";
		case MEM_STAT_OP_PFETCH:
			return "Pfetch";
		case MEM_STAT_OP_EXEC:
			return "Exec";
		case MEM_STAT_OP_OTHER:
		default:
			return "Other";
		}
	case PERF_MEM_STAT_CACHE:
		switch (idx) {
		case MEM_STAT_CACHE_L1:
			return "L1";
		case MEM_STAT_CACHE_L2:
			return "L2";
		case MEM_STAT_CACHE_L3:
			return "L3";
		case MEM_STAT_CACHE_L4:
			return "L4";
		case MEM_STAT_CACHE_L1_BUF:
			return "L1-buf";
		case MEM_STAT_CACHE_L2_BUF:
			return "L2-buf";
		case MEM_STAT_CACHE_OTHER:
		default:
			return "Other";
		}
	case PERF_MEM_STAT_MEMORY:
		switch (idx) {
		case MEM_STAT_MEMORY_RAM:
			return "RAM";
		case MEM_STAT_MEMORY_MSC:
			return "MSC";
		case MEM_STAT_MEMORY_UNC:
			return "Uncach";
		case MEM_STAT_MEMORY_CXL:
			return "CXL";
		case MEM_STAT_MEMORY_IO:
			return "IO";
		case MEM_STAT_MEMORY_PMEM:
			return "PMEM";
		case MEM_STAT_MEMORY_OTHER:
		default:
			return "Other";
		}
	case PERF_MEM_STAT_SNOOP:
		switch (idx) {
		case MEM_STAT_SNOOP_HIT:
			return "Hit";
		case MEM_STAT_SNOOP_HITM:
			return "HitM";
		case MEM_STAT_SNOOP_MISS:
			return "Miss";
		case MEM_STAT_SNOOP_OTHER:
		default:
			return "Other";
		}
	case PERF_MEM_STAT_DTLB:
		switch (idx) {
		case MEM_STAT_DTLB_L1_HIT:
			return "L1-Hit";
		case MEM_STAT_DTLB_L2_HIT:
			return "L2-Hit";
		case MEM_STAT_DTLB_ANY_HIT:
			return "L?-Hit";
		case MEM_STAT_DTLB_MISS:
			return "Miss";
		case MEM_STAT_DTLB_OTHER:
		default:
			return "Other";
		}
	default:
		break;
	}
	return "N/A";
}
