// SPDX-License-Identifier: GPL-2.0
#include <asm/cpu_device_id.h>
#include <asm/cpufeature.h>
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/slab.h>

/**
 * x86_match_vendor_cpu_type - helper function to match the hardware defined
 *                             cpu-type for a single entry in the x86_cpu_id
 *                             table. Note, this function does not match the
 *                             generic cpu-types TOPO_CPU_TYPE_EFFICIENCY and
 *                             TOPO_CPU_TYPE_PERFORMANCE.
 * @c: Pointer to the cpuinfo_x86 structure of the CPU to match.
 * @m: Pointer to the x86_cpu_id entry to match against.
 *
 * Return: true if the cpu-type matches, false otherwise.
 */
static bool x86_match_vendor_cpu_type(struct cpuinfo_x86 *c, const struct x86_cpu_id *m)
{
	if (m->type == X86_CPU_TYPE_ANY)
		return true;

	/* Hybrid CPUs are special, they are assumed to match all cpu-types */
	if (cpu_feature_enabled(X86_FEATURE_HYBRID_CPU))
		return true;

	if (c->x86_vendor == X86_VENDOR_INTEL)
		return m->type == c->topo.intel_type;
	if (c->x86_vendor == X86_VENDOR_AMD)
		return m->type == c->topo.amd_type;

	return false;
}

/**
 * x86_match_cpu - match current CPU against an array of x86_cpu_ids
 * @match: Pointer to array of x86_cpu_ids. Last entry terminated with
 *         {}.
 *
 * Return the entry if the current CPU matches the entries in the
 * passed x86_cpu_id match table. Otherwise NULL.  The match table
 * contains vendor (X86_VENDOR_*), family, model and feature bits or
 * respective wildcard entries.
 *
 * A typical table entry would be to match a specific CPU
 *
 * X86_MATCH_VFM_FEATURE(INTEL_BROADWELL, X86_FEATURE_ANY, NULL);
 *
 * Fields can be wildcarded with %X86_VENDOR_ANY, %X86_FAMILY_ANY,
 * %X86_MODEL_ANY, %X86_FEATURE_ANY (except for vendor)
 *
 * asm/cpu_device_id.h contains a set of useful macros which are shortcuts
 * for various common selections. The above can be shortened to:
 *
 * X86_MATCH_VFM(INTEL_BROADWELL, NULL);
 *
 * Arrays used to match for this should also be declared using
 * MODULE_DEVICE_TABLE(x86cpu, ...)
 *
 * This always matches against the boot cpu, assuming models and features are
 * consistent over all CPUs.
 */
const struct x86_cpu_id *x86_match_cpu(const struct x86_cpu_id *match)
{
	const struct x86_cpu_id *m;
	struct cpuinfo_x86 *c = &boot_cpu_data;

	for (m = match; m->flags & X86_CPU_ID_FLAG_ENTRY_VALID; m++) {
		if (m->vendor != X86_VENDOR_ANY && c->x86_vendor != m->vendor)
			continue;
		if (m->family != X86_FAMILY_ANY && c->x86 != m->family)
			continue;
		if (m->model != X86_MODEL_ANY && c->x86_model != m->model)
			continue;
		if (m->steppings != X86_STEPPING_ANY &&
		    !(BIT(c->x86_stepping) & m->steppings))
			continue;
		if (m->feature != X86_FEATURE_ANY && !cpu_has(c, m->feature))
			continue;
		if (!x86_match_vendor_cpu_type(c, m))
			continue;
		return m;
	}
	return NULL;
}
EXPORT_SYMBOL(x86_match_cpu);

bool x86_match_min_microcode_rev(const struct x86_cpu_id *table)
{
	const struct x86_cpu_id *res = x86_match_cpu(table);

	if (!res || res->driver_data > boot_cpu_data.microcode)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(x86_match_min_microcode_rev);
