// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/lib/vsprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/* vsprintf.c -- Lars Wirzenius & Linus Torvalds. */
/*
 * Wirzenius wrote this portably, Torvalds fucked it up :-)
 */

/*
 * Fri Jul 13 2001 Crutcher Dunnavant <crutcher+kernel@datastacks.com>
 * - changed to provide snprintf and vsnprintf functions
 * So Feb  1 16:51:32 CET 2004 Juergen Quade <quade@hsnr.de>
 * - scnprintf and vscnprintf
 */

#include <linux/stdarg.h>
#include <linux/build_bug.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/errname.h>
#include <linux/module.h>	/* for KSYM_SYMBOL_LEN */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/rtc.h>
#include <linux/sprintf.h>
#include <linux/time.h>
#include <linux/uuid.h>
#include <linux/of.h>
#include <net/addrconf.h>
#include <linux/siphash.h>
#include <linux/compiler.h>
#include <linux/property.h>
#include <linux/notifier.h>
#ifdef CONFIG_BLOCK
#include <linux/blkdev.h>
#endif

#include "../mm/internal.h"	/* For the trace_print_flags arrays */

#include <asm/page.h>		/* for PAGE_SIZE */
#include <asm/byteorder.h>	/* cpu_to_le16 */
#include <linux/unaligned.h>

#include <linux/string_helpers.h>
#include "kstrtox.h"

/* Disable pointer hashing if requested */
bool no_hash_pointers __ro_after_init;
EXPORT_SYMBOL_GPL(no_hash_pointers);

/*
 * Hashed pointers policy selected by "hash_pointers=..." boot param
 *
 * `auto`   - Hashed pointers enabled unless disabled by slub_debug_enabled=true
 * `always` - Hashed pointers enabled unconditionally
 * `never`  - Hashed pointers disabled unconditionally
 */
enum hash_pointers_policy {
	HASH_PTR_AUTO = 0,
	HASH_PTR_ALWAYS,
	HASH_PTR_NEVER
};
static enum hash_pointers_policy hash_pointers_mode __initdata;

noinline
static unsigned long long simple_strntoull(const char *startp, char **endp, unsigned int base, size_t max_chars)
{
	const char *cp;
	unsigned long long result = 0ULL;
	size_t prefix_chars;
	unsigned int rv;

	cp = _parse_integer_fixup_radix(startp, &base);
	prefix_chars = cp - startp;
	if (prefix_chars < max_chars) {
		rv = _parse_integer_limit(cp, base, &result, max_chars - prefix_chars);
		/* FIXME */
		cp += (rv & ~KSTRTOX_OVERFLOW);
	} else {
		/* Field too short for prefix + digit, skip over without converting */
		cp = startp + max_chars;
	}

	if (endp)
		*endp = (char *)cp;

	return result;
}

/**
 * simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoull instead.
 */
noinline
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	return simple_strntoull(cp, endp, base, INT_MAX);
}
EXPORT_SYMBOL(simple_strtoull);

/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoul instead.
 */
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base)
{
	return simple_strtoull(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtoul);

unsigned long simple_strntoul(const char *cp, char **endp, unsigned int base,
			      size_t max_chars)
{
	return simple_strntoull(cp, endp, base, max_chars);
}
EXPORT_SYMBOL(simple_strntoul);

/**
 * simple_strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtol instead.
 */
long simple_strtol(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoul(cp + 1, endp, base);

	return simple_strtoul(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtol);

noinline
static long long simple_strntoll(const char *cp, char **endp, unsigned int base, size_t max_chars)
{
	/*
	 * simple_strntoull() safely handles receiving max_chars==0 in the
	 * case cp[0] == '-' && max_chars == 1.
	 * If max_chars == 0 we can drop through and pass it to simple_strntoull()
	 * and the content of *cp is irrelevant.
	 */
	if (*cp == '-' && max_chars > 0)
		return -simple_strntoull(cp + 1, endp, base, max_chars - 1);

	return simple_strntoull(cp, endp, base, max_chars);
}

/**
 * simple_strtoll - convert a string to a signed long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoll instead.
 */
long long simple_strtoll(const char *cp, char **endp, unsigned int base)
{
	return simple_strntoll(cp, endp, base, INT_MAX);
}
EXPORT_SYMBOL(simple_strtoll);

static inline int skip_atoi(const char **s)
{
	int i = 0;

	do {
		i = i*10 + *((*s)++) - '0';
	} while (isdigit(**s));

	return i;
}

/*
 * Decimal conversion is by far the most typical, and is used for
 * /proc and /sys data. This directly impacts e.g. top performance
 * with many processes running. We optimize it for speed by emitting
 * two characters at a time, using a 200 byte lookup table. This
 * roughly halves the number of multiplications compared to computing
 * the digits one at a time. Implementation strongly inspired by the
 * previous version, which in turn used ideas described at
 * <http://www.cs.uiowa.edu/~jones/bcd/divide.html> (with permission
 * from the author, Douglas W. Jones).
 *
 * It turns out there is precisely one 26 bit fixed-point
 * approximation a of 64/100 for which x/100 == (x * (u64)a) >> 32
 * holds for all x in [0, 10^8-1], namely a = 0x28f5c29. The actual
 * range happens to be somewhat larger (x <= 1073741898), but that's
 * irrelevant for our purpose.
 *
 * For dividing a number in the range [10^4, 10^6-1] by 100, we still
 * need a 32x32->64 bit multiply, so we simply use the same constant.
 *
 * For dividing a number in the range [100, 10^4-1] by 100, there are
 * several options. The simplest is (x * 0x147b) >> 19, which is valid
 * for all x <= 43698.
 */

static const u16 decpair[100] = {
#define _(x) (__force u16) cpu_to_le16(((x % 10) | ((x / 10) << 8)) + 0x3030)
	_( 0), _( 1), _( 2), _( 3), _( 4), _( 5), _( 6), _( 7), _( 8), _( 9),
	_(10), _(11), _(12), _(13), _(14), _(15), _(16), _(17), _(18), _(19),
	_(20), _(21), _(22), _(23), _(24), _(25), _(26), _(27), _(28), _(29),
	_(30), _(31), _(32), _(33), _(34), _(35), _(36), _(37), _(38), _(39),
	_(40), _(41), _(42), _(43), _(44), _(45), _(46), _(47), _(48), _(49),
	_(50), _(51), _(52), _(53), _(54), _(55), _(56), _(57), _(58), _(59),
	_(60), _(61), _(62), _(63), _(64), _(65), _(66), _(67), _(68), _(69),
	_(70), _(71), _(72), _(73), _(74), _(75), _(76), _(77), _(78), _(79),
	_(80), _(81), _(82), _(83), _(84), _(85), _(86), _(87), _(88), _(89),
	_(90), _(91), _(92), _(93), _(94), _(95), _(96), _(97), _(98), _(99),
#undef _
};

/*
 * This will print a single '0' even if r == 0, since we would
 * immediately jump to out_r where two 0s would be written but only
 * one of them accounted for in buf. This is needed by ip4_string
 * below. All other callers pass a non-zero value of r.
*/
static noinline_for_stack
char *put_dec_trunc8(char *buf, unsigned r)
{
	unsigned q;

	/* 1 <= r < 10^8 */
	if (r < 100)
		goto out_r;

	/* 100 <= r < 10^8 */
	q = (r * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	/* 1 <= q < 10^6 */
	if (q < 100)
		goto out_q;

	/*  100 <= q < 10^6 */
	r = (q * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[q - 100*r];
	buf += 2;

	/* 1 <= r < 10^4 */
	if (r < 100)
		goto out_r;

	/* 100 <= r < 10^4 */
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;
out_q:
	/* 1 <= q < 100 */
	r = q;
out_r:
	/* 1 <= r < 100 */
	*((u16 *)buf) = decpair[r];
	buf += r < 10 ? 1 : 2;
	return buf;
}

#if BITS_PER_LONG == 64 && BITS_PER_LONG_LONG == 64
static noinline_for_stack
char *put_dec_full8(char *buf, unsigned r)
{
	unsigned q;

	/* 0 <= r < 10^8 */
	q = (r * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	/* 0 <= q < 10^6 */
	r = (q * (u64)0x28f5c29) >> 32;
	*((u16 *)buf) = decpair[q - 100*r];
	buf += 2;

	/* 0 <= r < 10^4 */
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;

	/* 0 <= q < 100 */
	*((u16 *)buf) = decpair[q];
	buf += 2;
	return buf;
}

static noinline_for_stack
char *put_dec(char *buf, unsigned long long n)
{
	if (n >= 100*1000*1000)
		buf = put_dec_full8(buf, do_div(n, 100*1000*1000));
	/* 1 <= n <= 1.6e11 */
	if (n >= 100*1000*1000)
		buf = put_dec_full8(buf, do_div(n, 100*1000*1000));
	/* 1 <= n < 1e8 */
	return put_dec_trunc8(buf, n);
}

#elif BITS_PER_LONG == 32 && BITS_PER_LONG_LONG == 64

static void
put_dec_full4(char *buf, unsigned r)
{
	unsigned q;

	/* 0 <= r < 10^4 */
	q = (r * 0x147b) >> 19;
	*((u16 *)buf) = decpair[r - 100*q];
	buf += 2;
	/* 0 <= q < 100 */
	*((u16 *)buf) = decpair[q];
}

/*
 * Call put_dec_full4 on x % 10000, return x / 10000.
 * The approximation x/10000 == (x * 0x346DC5D7) >> 43
 * holds for all x < 1,128,869,999.  The largest value this
 * helper will ever be asked to convert is 1,125,520,955.
 * (second call in the put_dec code, assuming n is all-ones).
 */
static noinline_for_stack
unsigned put_dec_helper4(char *buf, unsigned x)
{
        uint32_t q = (x * (uint64_t)0x346DC5D7) >> 43;

        put_dec_full4(buf, x - q * 10000);
        return q;
}

/* Based on code by Douglas W. Jones found at
 * <http://www.cs.uiowa.edu/~jones/bcd/decimal.html#sixtyfour>
 * (with permission from the author).
 * Performs no 64-bit division and hence should be fast on 32-bit machines.
 */
static
char *put_dec(char *buf, unsigned long long n)
{
	uint32_t d3, d2, d1, q, h;

	if (n < 100*1000*1000)
		return put_dec_trunc8(buf, n);

	d1  = ((uint32_t)n >> 16); /* implicit "& 0xffff" */
	h   = (n >> 32);
	d2  = (h      ) & 0xffff;
	d3  = (h >> 16); /* implicit "& 0xffff" */

	/* n = 2^48 d3 + 2^32 d2 + 2^16 d1 + d0
	     = 281_4749_7671_0656 d3 + 42_9496_7296 d2 + 6_5536 d1 + d0 */
	q   = 656 * d3 + 7296 * d2 + 5536 * d1 + ((uint32_t)n & 0xffff);
	q = put_dec_helper4(buf, q);

	q += 7671 * d3 + 9496 * d2 + 6 * d1;
	q = put_dec_helper4(buf+4, q);

	q += 4749 * d3 + 42 * d2;
	q = put_dec_helper4(buf+8, q);

	q += 281 * d3;
	buf += 12;
	if (q)
		buf = put_dec_trunc8(buf, q);
	else while (buf[-1] == '0')
		--buf;

	return buf;
}

#endif

/*
 * Convert passed number to decimal string.
 * Returns the length of string.  On buffer overflow, returns 0.
 *
 * If speed is not important, use snprintf(). It's easy to read the code.
 */
int num_to_str(char *buf, int size, unsigned long long num, unsigned int width)
{
	/* put_dec requires 2-byte alignment of the buffer. */
	char tmp[sizeof(num) * 3] __aligned(2);
	int idx, len;

	/* put_dec() may work incorrectly for num = 0 (generate "", not "0") */
	if (num <= 9) {
		tmp[0] = '0' + num;
		len = 1;
	} else {
		len = put_dec(tmp, num) - tmp;
	}

	if (len > size || width > size)
		return 0;

	if (width > len) {
		width = width - len;
		for (idx = 0; idx < width; idx++)
			buf[idx] = ' ';
	} else {
		width = 0;
	}

	for (idx = 0; idx < len; ++idx)
		buf[idx + width] = tmp[len - idx - 1];

	return len + width;
}

#define SIGN	1		/* unsigned/signed */
#define LEFT	2		/* left justified */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define ZEROPAD	16		/* pad with zero, must be 16 == '0' - ' ' */
#define SMALL	32		/* use lowercase in hex (must be 32 == 0x20) */
#define SPECIAL	64		/* prefix hex with "0x", octal with "0" */

static_assert(ZEROPAD == ('0' - ' '));
static_assert(SMALL == ('a' ^ 'A'));

enum format_state {
	FORMAT_STATE_NONE, /* Just a string part */
	FORMAT_STATE_NUM,
	FORMAT_STATE_WIDTH,
	FORMAT_STATE_PRECISION,
	FORMAT_STATE_CHAR,
	FORMAT_STATE_STR,
	FORMAT_STATE_PTR,
	FORMAT_STATE_PERCENT_CHAR,
	FORMAT_STATE_INVALID,
};

struct printf_spec {
	unsigned char	flags;		/* flags to number() */
	unsigned char	base;		/* number base, 8, 10 or 16 only */
	short		precision;	/* # of digits/chars */
	int		field_width;	/* width of output field */
} __packed;
static_assert(sizeof(struct printf_spec) == 8);

#define FIELD_WIDTH_MAX ((1 << 23) - 1)
#define PRECISION_MAX ((1 << 15) - 1)

static noinline_for_stack
char *number(char *buf, char *end, unsigned long long num,
	     struct printf_spec spec)
{
	/* put_dec requires 2-byte alignment of the buffer. */
	char tmp[3 * sizeof(num)] __aligned(2);
	char sign;
	char locase;
	int need_pfx = ((spec.flags & SPECIAL) && spec.base != 10);
	int i;
	bool is_zero = num == 0LL;
	int field_width = spec.field_width;
	int precision = spec.precision;

	/* locase = 0 or 0x20. ORing digits or letters with 'locase'
	 * produces same digits or (maybe lowercased) letters */
	locase = (spec.flags & SMALL);
	if (spec.flags & LEFT)
		spec.flags &= ~ZEROPAD;
	sign = 0;
	if (spec.flags & SIGN) {
		if ((signed long long)num < 0) {
			sign = '-';
			num = -(signed long long)num;
			field_width--;
		} else if (spec.flags & PLUS) {
			sign = '+';
			field_width--;
		} else if (spec.flags & SPACE) {
			sign = ' ';
			field_width--;
		}
	}
	if (need_pfx) {
		if (spec.base == 16)
			field_width -= 2;
		else if (!is_zero)
			field_width--;
	}

	/* generate full string in tmp[], in reverse order */
	i = 0;
	if (num < spec.base)
		tmp[i++] = hex_asc_upper[num] | locase;
	else if (spec.base != 10) { /* 8 or 16 */
		int mask = spec.base - 1;
		int shift = 3;

		if (spec.base == 16)
			shift = 4;
		do {
			tmp[i++] = (hex_asc_upper[((unsigned char)num) & mask] | locase);
			num >>= shift;
		} while (num);
	} else { /* base 10 */
		i = put_dec(tmp, num) - tmp;
	}

	/* printing 100 using %2d gives "100", not "00" */
	if (i > precision)
		precision = i;
	/* leading space padding */
	field_width -= precision;
	if (!(spec.flags & (ZEROPAD | LEFT))) {
		while (--field_width >= 0) {
			if (buf < end)
				*buf = ' ';
			++buf;
		}
	}
	/* sign */
	if (sign) {
		if (buf < end)
			*buf = sign;
		++buf;
	}
	/* "0x" / "0" prefix */
	if (need_pfx) {
		if (spec.base == 16 || !is_zero) {
			if (buf < end)
				*buf = '0';
			++buf;
		}
		if (spec.base == 16) {
			if (buf < end)
				*buf = ('X' | locase);
			++buf;
		}
	}
	/* zero or space padding */
	if (!(spec.flags & LEFT)) {
		char c = ' ' + (spec.flags & ZEROPAD);

		while (--field_width >= 0) {
			if (buf < end)
				*buf = c;
			++buf;
		}
	}
	/* hmm even more zero padding? */
	while (i <= --precision) {
		if (buf < end)
			*buf = '0';
		++buf;
	}
	/* actual digits of result */
	while (--i >= 0) {
		if (buf < end)
			*buf = tmp[i];
		++buf;
	}
	/* trailing space padding */
	while (--field_width >= 0) {
		if (buf < end)
			*buf = ' ';
		++buf;
	}

	return buf;
}

static noinline_for_stack
char *special_hex_number(char *buf, char *end, unsigned long long num, int size)
{
	struct printf_spec spec;

	spec.field_width = 2 + 2 * size;	/* 0x + hex */
	spec.flags = SPECIAL | SMALL | ZEROPAD;
	spec.base = 16;
	spec.precision = -1;

	return number(buf, end, num, spec);
}

static void move_right(char *buf, char *end, unsigned len, unsigned spaces)
{
	size_t size;
	if (buf >= end)	/* nowhere to put anything */
		return;
	size = end - buf;
	if (size <= spaces) {
		memset(buf, ' ', size);
		return;
	}
	if (len) {
		if (len > size - spaces)
			len = size - spaces;
		memmove(buf + spaces, buf, len);
	}
	memset(buf, ' ', spaces);
}

/*
 * Handle field width padding for a string.
 * @buf: current buffer position
 * @n: length of string
 * @end: end of output buffer
 * @spec: for field width and flags
 * Returns: new buffer position after padding.
 */
static noinline_for_stack
char *widen_string(char *buf, int n, char *end, struct printf_spec spec)
{
	unsigned spaces;

	if (likely(n >= spec.field_width))
		return buf;
	/* we want to pad the sucker */
	spaces = spec.field_width - n;
	if (!(spec.flags & LEFT)) {
		move_right(buf - n, end, n, spaces);
		return buf + spaces;
	}
	while (spaces--) {
		if (buf < end)
			*buf = ' ';
		++buf;
	}
	return buf;
}

/* Handle string from a well known address. */
static char *string_nocheck(char *buf, char *end, const char *s,
			    struct printf_spec spec)
{
	int len = 0;
	int lim = spec.precision;

	while (lim--) {
		char c = *s++;
		if (!c)
			break;
		if (buf < end)
			*buf = c;
		++buf;
		++len;
	}
	return widen_string(buf, len, end, spec);
}

static char *err_ptr(char *buf, char *end, void *ptr,
		     struct printf_spec spec)
{
	int err = PTR_ERR(ptr);
	const char *sym = errname(err);

	if (sym)
		return string_nocheck(buf, end, sym, spec);

	/*
	 * Somebody passed ERR_PTR(-1234) or some other non-existing
	 * Efoo - or perhaps CONFIG_SYMBOLIC_ERRNAME=n. Fall back to
	 * printing it as its decimal representation.
	 */
	spec.flags |= SIGN;
	spec.base = 10;
	return number(buf, end, err, spec);
}

/* Be careful: error messages must fit into the given buffer. */
static char *error_string(char *buf, char *end, const char *s,
			  struct printf_spec spec)
{
	/*
	 * Hard limit to avoid a completely insane messages. It actually
	 * works pretty well because most error messages are in
	 * the many pointer format modifiers.
	 */
	if (spec.precision == -1)
		spec.precision = 2 * sizeof(void *);

	return string_nocheck(buf, end, s, spec);
}

/*
 * Do not call any complex external code here. Nested printk()/vsprintf()
 * might cause infinite loops. Failures might break printk() and would
 * be hard to debug.
 */
static const char *check_pointer_msg(const void *ptr)
{
	if (!ptr)
		return "(null)";

	if ((unsigned long)ptr < PAGE_SIZE || IS_ERR_VALUE(ptr))
		return "(efault)";

	return NULL;
}

static int check_pointer(char **buf, char *end, const void *ptr,
			 struct printf_spec spec)
{
	const char *err_msg;

	err_msg = check_pointer_msg(ptr);
	if (err_msg) {
		*buf = error_string(*buf, end, err_msg, spec);
		return -EFAULT;
	}

	return 0;
}

static noinline_for_stack
char *string(char *buf, char *end, const char *s,
	     struct printf_spec spec)
{
	if (check_pointer(&buf, end, s, spec))
		return buf;

	return string_nocheck(buf, end, s, spec);
}

static char *pointer_string(char *buf, char *end,
			    const void *ptr,
			    struct printf_spec spec)
{
	spec.base = 16;
	spec.flags |= SMALL;
	if (spec.field_width == -1) {
		spec.field_width = 2 * sizeof(ptr);
		spec.flags |= ZEROPAD;
	}

	return number(buf, end, (unsigned long int)ptr, spec);
}

/* Make pointers available for printing early in the boot sequence. */
static int debug_boot_weak_hash __ro_after_init;

static int __init debug_boot_weak_hash_enable(char *str)
{
	debug_boot_weak_hash = 1;
	pr_info("debug_boot_weak_hash enabled\n");
	return 0;
}
early_param("debug_boot_weak_hash", debug_boot_weak_hash_enable);

static bool filled_random_ptr_key __read_mostly;
static siphash_key_t ptr_key __read_mostly;

static int fill_ptr_key(struct notifier_block *nb, unsigned long action, void *data)
{
	get_random_bytes(&ptr_key, sizeof(ptr_key));

	/* Pairs with smp_rmb() before reading ptr_key. */
	smp_wmb();
	WRITE_ONCE(filled_random_ptr_key, true);
	return NOTIFY_DONE;
}

static int __init vsprintf_init_hashval(void)
{
	static struct notifier_block fill_ptr_key_nb = { .notifier_call = fill_ptr_key };
	execute_with_initialized_rng(&fill_ptr_key_nb);
	return 0;
}
subsys_initcall(vsprintf_init_hashval)

/* Maps a pointer to a 32 bit unique identifier. */
static inline int __ptr_to_hashval(const void *ptr, unsigned long *hashval_out)
{
	unsigned long hashval;

	if (!READ_ONCE(filled_random_ptr_key))
		return -EBUSY;

	/* Pairs with smp_wmb() after writing ptr_key. */
	smp_rmb();

#ifdef CONFIG_64BIT
	hashval = (unsigned long)siphash_1u64((u64)ptr, &ptr_key);
	/*
	 * Mask off the first 32 bits, this makes explicit that we have
	 * modified the address (and 32 bits is plenty for a unique ID).
	 */
	hashval = hashval & 0xffffffff;
#else
	hashval = (unsigned long)siphash_1u32((u32)ptr, &ptr_key);
#endif
	*hashval_out = hashval;
	return 0;
}

int ptr_to_hashval(const void *ptr, unsigned long *hashval_out)
{
	return __ptr_to_hashval(ptr, hashval_out);
}

static char *ptr_to_id(char *buf, char *end, const void *ptr,
		       struct printf_spec spec)
{
	const char *str = sizeof(ptr) == 8 ? "(____ptrval____)" : "(ptrval)";
	unsigned long hashval;
	int ret;

	/*
	 * Print the real pointer value for NULL and error pointers,
	 * as they are not actual addresses.
	 */
	if (IS_ERR_OR_NULL(ptr))
		return pointer_string(buf, end, ptr, spec);

	/* When debugging early boot use non-cryptographically secure hash. */
	if (unlikely(debug_boot_weak_hash)) {
		hashval = hash_long((unsigned long)ptr, 32);
		return pointer_string(buf, end, (const void *)hashval, spec);
	}

	ret = __ptr_to_hashval(ptr, &hashval);
	if (ret) {
		spec.field_width = 2 * sizeof(ptr);
		/* string length must be less than default_width */
		return error_string(buf, end, str, spec);
	}

	return pointer_string(buf, end, (const void *)hashval, spec);
}

static char *default_pointer(char *buf, char *end, const void *ptr,
			     struct printf_spec spec)
{
	/*
	 * default is to _not_ leak addresses, so hash before printing,
	 * unless no_hash_pointers is specified on the command line.
	 */
	if (unlikely(no_hash_pointers))
		return pointer_string(buf, end, ptr, spec);

	return ptr_to_id(buf, end, ptr, spec);
}

int kptr_restrict __read_mostly;

static noinline_for_stack
char *restricted_pointer(char *buf, char *end, const void *ptr,
			 struct printf_spec spec)
{
	switch (kptr_restrict) {
	case 0:
		/* Handle as %p, hash and do _not_ leak addresses. */
		return default_pointer(buf, end, ptr, spec);
	case 1: {
		const struct cred *cred;

		/*
		 * kptr_restrict==1 cannot be used in IRQ context
		 * because its test for CAP_SYSLOG would be meaningless.
		 */
		if (in_hardirq() || in_serving_softirq() || in_nmi()) {
			if (spec.field_width == -1)
				spec.field_width = 2 * sizeof(ptr);
			return error_string(buf, end, "pK-error", spec);
		}

		/*
		 * Only print the real pointer value if the current
		 * process has CAP_SYSLOG and is running with the
		 * same credentials it started with. This is because
		 * access to files is checked at open() time, but %pK
		 * checks permission at read() time. We don't want to
		 * leak pointer values if a binary opens a file using
		 * %pK and then elevates privileges before reading it.
		 */
		cred = current_cred();
		if (!has_capability_noaudit(current, CAP_SYSLOG) ||
		    !uid_eq(cred->euid, cred->uid) ||
		    !gid_eq(cred->egid, cred->gid))
			ptr = NULL;
		break;
	}
	case 2:
	default:
		/* Always print 0's for %pK */
		ptr = NULL;
		break;
	}

	return pointer_string(buf, end, ptr, spec);
}

static noinline_for_stack
char *dentry_name(char *buf, char *end, const struct dentry *d, struct printf_spec spec,
		  const char *fmt)
{
	const char *array[4], *s;
	const struct dentry *p;
	int depth;
	int i, n;

	switch (fmt[1]) {
		case '2': case '3': case '4':
			depth = fmt[1] - '0';
			break;
		default:
			depth = 1;
	}

	rcu_read_lock();
	for (i = 0; i < depth; i++, d = p) {
		if (check_pointer(&buf, end, d, spec)) {
			rcu_read_unlock();
			return buf;
		}

		p = READ_ONCE(d->d_parent);
		array[i] = READ_ONCE(d->d_name.name);
		if (p == d) {
			if (i)
				array[i] = "";
			i++;
			break;
		}
	}
	s = array[--i];
	for (n = 0; n != spec.precision; n++, buf++) {
		char c = *s++;
		if (!c) {
			if (!i)
				break;
			c = '/';
			s = array[--i];
		}
		if (buf < end)
			*buf = c;
	}
	rcu_read_unlock();
	return widen_string(buf, n, end, spec);
}

static noinline_for_stack
char *file_dentry_name(char *buf, char *end, const struct file *f,
			struct printf_spec spec, const char *fmt)
{
	if (check_pointer(&buf, end, f, spec))
		return buf;

	return dentry_name(buf, end, f->f_path.dentry, spec, fmt);
}
#ifdef CONFIG_BLOCK
static noinline_for_stack
char *bdev_name(char *buf, char *end, struct block_device *bdev,
		struct printf_spec spec, const char *fmt)
{
	struct gendisk *hd;

	if (check_pointer(&buf, end, bdev, spec))
		return buf;

	hd = bdev->bd_disk;
	buf = string(buf, end, hd->disk_name, spec);
	if (bdev_is_partition(bdev)) {
		if (isdigit(hd->disk_name[strlen(hd->disk_name)-1])) {
			if (buf < end)
				*buf = 'p';
			buf++;
		}
		buf = number(buf, end, bdev_partno(bdev), spec);
	}
	return buf;
}
#endif

static noinline_for_stack
char *symbol_string(char *buf, char *end, void *ptr,
		    struct printf_spec spec, const char *fmt)
{
	unsigned long value;
#ifdef CONFIG_KALLSYMS
	char sym[KSYM_SYMBOL_LEN];
#endif

	if (fmt[1] == 'R')
		ptr = __builtin_extract_return_addr(ptr);
	value = (unsigned long)ptr;

#ifdef CONFIG_KALLSYMS
	if (*fmt == 'B' && fmt[1] == 'b')
		sprint_backtrace_build_id(sym, value);
	else if (*fmt == 'B')
		sprint_backtrace(sym, value);
	else if (*fmt == 'S' && (fmt[1] == 'b' || (fmt[1] == 'R' && fmt[2] == 'b')))
		sprint_symbol_build_id(sym, value);
	else if (*fmt != 's')
		sprint_symbol(sym, value);
	else
		sprint_symbol_no_offset(sym, value);

	return string_nocheck(buf, end, sym, spec);
#else
	return special_hex_number(buf, end, value, sizeof(void *));
#endif
}

static const struct printf_spec default_str_spec = {
	.field_width = -1,
	.precision = -1,
};

static const struct printf_spec default_flag_spec = {
	.base = 16,
	.precision = -1,
	.flags = SPECIAL | SMALL,
};

static const struct printf_spec default_dec_spec = {
	.base = 10,
	.precision = -1,
};

static const struct printf_spec default_dec02_spec = {
	.base = 10,
	.field_width = 2,
	.precision = -1,
	.flags = ZEROPAD,
};

static const struct printf_spec default_dec04_spec = {
	.base = 10,
	.field_width = 4,
	.precision = -1,
	.flags = ZEROPAD,
};

static noinline_for_stack
char *hex_range(char *buf, char *end, u64 start_val, u64 end_val,
		struct printf_spec spec)
{
	buf = number(buf, end, start_val, spec);
	if (start_val == end_val)
		return buf;

	if (buf < end)
		*buf = '-';
	++buf;
	return number(buf, end, end_val, spec);
}

static noinline_for_stack
char *resource_string(char *buf, char *end, struct resource *res,
		      struct printf_spec spec, const char *fmt)
{
#ifndef IO_RSRC_PRINTK_SIZE
#define IO_RSRC_PRINTK_SIZE	6
#endif

#ifndef MEM_RSRC_PRINTK_SIZE
#define MEM_RSRC_PRINTK_SIZE	10
#endif
	static const struct printf_spec io_spec = {
		.base = 16,
		.field_width = IO_RSRC_PRINTK_SIZE,
		.precision = -1,
		.flags = SPECIAL | SMALL | ZEROPAD,
	};
	static const struct printf_spec mem_spec = {
		.base = 16,
		.field_width = MEM_RSRC_PRINTK_SIZE,
		.precision = -1,
		.flags = SPECIAL | SMALL | ZEROPAD,
	};
	static const struct printf_spec bus_spec = {
		.base = 16,
		.field_width = 2,
		.precision = -1,
		.flags = SMALL | ZEROPAD,
	};
	static const struct printf_spec str_spec = {
		.field_width = -1,
		.precision = 10,
		.flags = LEFT,
	};

	/* 32-bit res (sizeof==4): 10 chars in dec, 10 in hex ("0x" + 8)
	 * 64-bit res (sizeof==8): 20 chars in dec, 18 in hex ("0x" + 16) */
#define RSRC_BUF_SIZE		((2 * sizeof(resource_size_t)) + 4)
#define FLAG_BUF_SIZE		(2 * sizeof(res->flags))
#define DECODED_BUF_SIZE	sizeof("[mem - 64bit pref window disabled]")
#define RAW_BUF_SIZE		sizeof("[mem - flags 0x]")
	char sym[MAX(2*RSRC_BUF_SIZE + DECODED_BUF_SIZE,
		     2*RSRC_BUF_SIZE + FLAG_BUF_SIZE + RAW_BUF_SIZE)];

	char *p = sym, *pend = sym + sizeof(sym);
	int decode = (fmt[0] == 'R') ? 1 : 0;
	const struct printf_spec *specp;

	if (check_pointer(&buf, end, res, spec))
		return buf;

	*p++ = '[';
	if (res->flags & IORESOURCE_IO) {
		p = string_nocheck(p, pend, "io  ", str_spec);
		specp = &io_spec;
	} else if (res->flags & IORESOURCE_MEM) {
		p = string_nocheck(p, pend, "mem ", str_spec);
		specp = &mem_spec;
	} else if (res->flags & IORESOURCE_IRQ) {
		p = string_nocheck(p, pend, "irq ", str_spec);
		specp = &default_dec_spec;
	} else if (res->flags & IORESOURCE_DMA) {
		p = string_nocheck(p, pend, "dma ", str_spec);
		specp = &default_dec_spec;
	} else if (res->flags & IORESOURCE_BUS) {
		p = string_nocheck(p, pend, "bus ", str_spec);
		specp = &bus_spec;
	} else {
		p = string_nocheck(p, pend, "??? ", str_spec);
		specp = &mem_spec;
		decode = 0;
	}
	if (decode && res->flags & IORESOURCE_UNSET) {
		p = string_nocheck(p, pend, "size ", str_spec);
		p = number(p, pend, resource_size(res), *specp);
	} else {
		p = hex_range(p, pend, res->start, res->end, *specp);
	}
	if (decode) {
		if (res->flags & IORESOURCE_MEM_64)
			p = string_nocheck(p, pend, " 64bit", str_spec);
		if (res->flags & IORESOURCE_PREFETCH)
			p = string_nocheck(p, pend, " pref", str_spec);
		if (res->flags & IORESOURCE_WINDOW)
			p = string_nocheck(p, pend, " window", str_spec);
		if (res->flags & IORESOURCE_DISABLED)
			p = string_nocheck(p, pend, " disabled", str_spec);
	} else {
		p = string_nocheck(p, pend, " flags ", str_spec);
		p = number(p, pend, res->flags, default_flag_spec);
	}
	*p++ = ']';
	*p = '\0';

	return string_nocheck(buf, end, sym, spec);
}

static noinline_for_stack
char *range_string(char *buf, char *end, const struct range *range,
		   struct printf_spec spec, const char *fmt)
{
	char sym[sizeof("[range 0x0123456789abcdef-0x0123456789abcdef]")];
	char *p = sym, *pend = sym + sizeof(sym);

	struct printf_spec range_spec = {
		.field_width = 2 + 2 * sizeof(range->start), /* 0x + 2 * 8 */
		.flags = SPECIAL | SMALL | ZEROPAD,
		.base = 16,
		.precision = -1,
	};

	if (check_pointer(&buf, end, range, spec))
		return buf;

	p = string_nocheck(p, pend, "[range ", default_str_spec);
	p = hex_range(p, pend, range->start, range->end, range_spec);
	*p++ = ']';
	*p = '\0';

	return string_nocheck(buf, end, sym, spec);
}

static noinline_for_stack
char *hex_string(char *buf, char *end, u8 *addr, struct printf_spec spec,
		 const char *fmt)
{
	int i, len = 1;		/* if we pass '%ph[CDN]', field width remains
				   negative value, fallback to the default */
	char separator;

	if (spec.field_width == 0)
		/* nothing to print */
		return buf;

	if (check_pointer(&buf, end, addr, spec))
		return buf;

	switch (fmt[1]) {
	case 'C':
		separator = ':';
		break;
	case 'D':
		separator = '-';
		break;
	case 'N':
		separator = 0;
		break;
	default:
		separator = ' ';
		break;
	}

	if (spec.field_width > 0)
		len = min_t(int, spec.field_width, 64);

	for (i = 0; i < len; ++i) {
		if (buf < end)
			*buf = hex_asc_hi(addr[i]);
		++buf;
		if (buf < end)
			*buf = hex_asc_lo(addr[i]);
		++buf;

		if (separator && i != len - 1) {
			if (buf < end)
				*buf = separator;
			++buf;
		}
	}

	return buf;
}

static noinline_for_stack
char *bitmap_string(char *buf, char *end, const unsigned long *bitmap,
		    struct printf_spec spec, const char *fmt)
{
	const int CHUNKSZ = 32;
	int nr_bits = max_t(int, spec.field_width, 0);
	int i, chunksz;
	bool first = true;

	if (check_pointer(&buf, end, bitmap, spec))
		return buf;

	/* reused to print numbers */
	spec = (struct printf_spec){ .flags = SMALL | ZEROPAD, .base = 16 };

	chunksz = nr_bits & (CHUNKSZ - 1);
	if (chunksz == 0)
		chunksz = CHUNKSZ;

	i = ALIGN(nr_bits, CHUNKSZ) - CHUNKSZ;
	for (; i >= 0; i -= CHUNKSZ) {
		u32 chunkmask, val;
		int word, bit;

		chunkmask = ((1ULL << chunksz) - 1);
		word = i / BITS_PER_LONG;
		bit = i % BITS_PER_LONG;
		val = (bitmap[word] >> bit) & chunkmask;

		if (!first) {
			if (buf < end)
				*buf = ',';
			buf++;
		}
		first = false;

		spec.field_width = DIV_ROUND_UP(chunksz, 4);
		buf = number(buf, end, val, spec);

		chunksz = CHUNKSZ;
	}
	return buf;
}

static noinline_for_stack
char *bitmap_list_string(char *buf, char *end, const unsigned long *bitmap,
			 struct printf_spec spec, const char *fmt)
{
	int nr_bits = max_t(int, spec.field_width, 0);
	bool first = true;
	int rbot, rtop;

	if (check_pointer(&buf, end, bitmap, spec))
		return buf;

	for_each_set_bitrange(rbot, rtop, bitmap, nr_bits) {
		if (!first) {
			if (buf < end)
				*buf = ',';
			buf++;
		}
		first = false;

		buf = number(buf, end, rbot, default_dec_spec);
		if (rtop == rbot + 1)
			continue;

		if (buf < end)
			*buf = '-';
		buf = number(++buf, end, rtop - 1, default_dec_spec);
	}
	return buf;
}

static noinline_for_stack
char *mac_address_string(char *buf, char *end, u8 *addr,
			 struct printf_spec spec, const char *fmt)
{
	char mac_addr[sizeof("xx:xx:xx:xx:xx:xx")];
	char *p = mac_addr;
	int i;
	char separator;
	bool reversed = false;

	if (check_pointer(&buf, end, addr, spec))
		return buf;

	switch (fmt[1]) {
	case 'F':
		separator = '-';
		break;

	case 'R':
		reversed = true;
		fallthrough;

	default:
		separator = ':';
		break;
	}

	for (i = 0; i < 6; i++) {
		if (reversed)
			p = hex_byte_pack(p, addr[5 - i]);
		else
			p = hex_byte_pack(p, addr[i]);

		if (fmt[0] == 'M' && i != 5)
			*p++ = separator;
	}
	*p = '\0';

	return string_nocheck(buf, end, mac_addr, spec);
}

static noinline_for_stack
char *ip4_string(char *p, const u8 *addr, const char *fmt)
{
	int i;
	bool leading_zeros = (fmt[0] == 'i');
	int index;
	int step;

	switch (fmt[2]) {
	case 'h':
#ifdef __BIG_ENDIAN
		index = 0;
		step = 1;
#else
		index = 3;
		step = -1;
#endif
		break;
	case 'l':
		index = 3;
		step = -1;
		break;
	case 'n':
	case 'b':
	default:
		index = 0;
		step = 1;
		break;
	}
	for (i = 0; i < 4; i++) {
		char temp[4] __aligned(2);	/* hold each IP quad in reverse order */
		int digits = put_dec_trunc8(temp, addr[index]) - temp;
		if (leading_zeros) {
			if (digits < 3)
				*p++ = '0';
			if (digits < 2)
				*p++ = '0';
		}
		/* reverse the digits in the quad */
		while (digits--)
			*p++ = temp[digits];
		if (i < 3)
			*p++ = '.';
		index += step;
	}
	*p = '\0';

	return p;
}

static noinline_for_stack
char *ip6_compressed_string(char *p, const char *addr)
{
	int i, j, range;
	unsigned char zerolength[8];
	int longest = 1;
	int colonpos = -1;
	u16 word;
	u8 hi, lo;
	bool needcolon = false;
	bool useIPv4;
	struct in6_addr in6;

	memcpy(&in6, addr, sizeof(struct in6_addr));

	useIPv4 = ipv6_addr_v4mapped(&in6) || ipv6_addr_is_isatap(&in6);

	memset(zerolength, 0, sizeof(zerolength));

	if (useIPv4)
		range = 6;
	else
		range = 8;

	/* find position of longest 0 run */
	for (i = 0; i < range; i++) {
		for (j = i; j < range; j++) {
			if (in6.s6_addr16[j] != 0)
				break;
			zerolength[i]++;
		}
	}
	for (i = 0; i < range; i++) {
		if (zerolength[i] > longest) {
			longest = zerolength[i];
			colonpos = i;
		}
	}
	if (longest == 1)		/* don't compress a single 0 */
		colonpos = -1;

	/* emit address */
	for (i = 0; i < range; i++) {
		if (i == colonpos) {
			if (needcolon || i == 0)
				*p++ = ':';
			*p++ = ':';
			needcolon = false;
			i += longest - 1;
			continue;
		}
		if (needcolon) {
			*p++ = ':';
			needcolon = false;
		}
		/* hex u16 without leading 0s */
		word = ntohs(in6.s6_addr16[i]);
		hi = word >> 8;
		lo = word & 0xff;
		if (hi) {
			if (hi > 0x0f)
				p = hex_byte_pack(p, hi);
			else
				*p++ = hex_asc_lo(hi);
			p = hex_byte_pack(p, lo);
		}
		else if (lo > 0x0f)
			p = hex_byte_pack(p, lo);
		else
			*p++ = hex_asc_lo(lo);
		needcolon = true;
	}

	if (useIPv4) {
		if (needcolon)
			*p++ = ':';
		p = ip4_string(p, &in6.s6_addr[12], "I4");
	}
	*p = '\0';

	return p;
}

static noinline_for_stack
char *ip6_string(char *p, const char *addr, const char *fmt)
{
	int i;

	for (i = 0; i < 8; i++) {
		p = hex_byte_pack(p, *addr++);
		p = hex_byte_pack(p, *addr++);
		if (fmt[0] == 'I' && i != 7)
			*p++ = ':';
	}
	*p = '\0';

	return p;
}

static noinline_for_stack
char *ip6_addr_string(char *buf, char *end, const u8 *addr,
		      struct printf_spec spec, const char *fmt)
{
	char ip6_addr[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];

	if (fmt[0] == 'I' && fmt[2] == 'c')
		ip6_compressed_string(ip6_addr, addr);
	else
		ip6_string(ip6_addr, addr, fmt);

	return string_nocheck(buf, end, ip6_addr, spec);
}

static noinline_for_stack
char *ip4_addr_string(char *buf, char *end, const u8 *addr,
		      struct printf_spec spec, const char *fmt)
{
	char ip4_addr[sizeof("255.255.255.255")];

	ip4_string(ip4_addr, addr, fmt);

	return string_nocheck(buf, end, ip4_addr, spec);
}

static noinline_for_stack
char *ip6_addr_string_sa(char *buf, char *end, const struct sockaddr_in6 *sa,
			 struct printf_spec spec, const char *fmt)
{
	bool have_p = false, have_s = false, have_f = false, have_c = false;
	char ip6_addr[sizeof("[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255]") +
		      sizeof(":12345") + sizeof("/123456789") +
		      sizeof("%1234567890")];
	char *p = ip6_addr, *pend = ip6_addr + sizeof(ip6_addr);
	const u8 *addr = (const u8 *) &sa->sin6_addr;
	char fmt6[2] = { fmt[0], '6' };
	u8 off = 0;

	fmt++;
	while (isalpha(*++fmt)) {
		switch (*fmt) {
		case 'p':
			have_p = true;
			break;
		case 'f':
			have_f = true;
			break;
		case 's':
			have_s = true;
			break;
		case 'c':
			have_c = true;
			break;
		}
	}

	if (have_p || have_s || have_f) {
		*p = '[';
		off = 1;
	}

	if (fmt6[0] == 'I' && have_c)
		p = ip6_compressed_string(ip6_addr + off, addr);
	else
		p = ip6_string(ip6_addr + off, addr, fmt6);

	if (have_p || have_s || have_f)
		*p++ = ']';

	if (have_p) {
		*p++ = ':';
		p = number(p, pend, ntohs(sa->sin6_port), spec);
	}
	if (have_f) {
		*p++ = '/';
		p = number(p, pend, ntohl(sa->sin6_flowinfo &
					  IPV6_FLOWINFO_MASK), spec);
	}
	if (have_s) {
		*p++ = '%';
		p = number(p, pend, sa->sin6_scope_id, spec);
	}
	*p = '\0';

	return string_nocheck(buf, end, ip6_addr, spec);
}

static noinline_for_stack
char *ip4_addr_string_sa(char *buf, char *end, const struct sockaddr_in *sa,
			 struct printf_spec spec, const char *fmt)
{
	bool have_p = false;
	char *p, ip4_addr[sizeof("255.255.255.255") + sizeof(":12345")];
	char *pend = ip4_addr + sizeof(ip4_addr);
	const u8 *addr = (const u8 *) &sa->sin_addr.s_addr;
	char fmt4[3] = { fmt[0], '4', 0 };

	fmt++;
	while (isalpha(*++fmt)) {
		switch (*fmt) {
		case 'p':
			have_p = true;
			break;
		case 'h':
		case 'l':
		case 'n':
		case 'b':
			fmt4[2] = *fmt;
			break;
		}
	}

	p = ip4_string(ip4_addr, addr, fmt4);
	if (have_p) {
		*p++ = ':';
		p = number(p, pend, ntohs(sa->sin_port), spec);
	}
	*p = '\0';

	return string_nocheck(buf, end, ip4_addr, spec);
}

static noinline_for_stack
char *ip_addr_string(char *buf, char *end, const void *ptr,
		     struct printf_spec spec, const char *fmt)
{
	char *err_fmt_msg;

	if (check_pointer(&buf, end, ptr, spec))
		return buf;

	switch (fmt[1]) {
	case '6':
		return ip6_addr_string(buf, end, ptr, spec, fmt);
	case '4':
		return ip4_addr_string(buf, end, ptr, spec, fmt);
	case 'S': {
		const union {
			struct sockaddr		raw;
			struct sockaddr_in	v4;
			struct sockaddr_in6	v6;
		} *sa = ptr;

		switch (sa->raw.sa_family) {
		case AF_INET:
			return ip4_addr_string_sa(buf, end, &sa->v4, spec, fmt);
		case AF_INET6:
			return ip6_addr_string_sa(buf, end, &sa->v6, spec, fmt);
		default:
			return error_string(buf, end, "(einval)", spec);
		}}
	}

	err_fmt_msg = fmt[0] == 'i' ? "(%pi?)" : "(%pI?)";
	return error_string(buf, end, err_fmt_msg, spec);
}

static noinline_for_stack
char *escaped_string(char *buf, char *end, u8 *addr, struct printf_spec spec,
		     const char *fmt)
{
	bool found = true;
	int count = 1;
	unsigned int flags = 0;
	int len;

	if (spec.field_width == 0)
		return buf;				/* nothing to print */

	if (check_pointer(&buf, end, addr, spec))
		return buf;

	do {
		switch (fmt[count++]) {
		case 'a':
			flags |= ESCAPE_ANY;
			break;
		case 'c':
			flags |= ESCAPE_SPECIAL;
			break;
		case 'h':
			flags |= ESCAPE_HEX;
			break;
		case 'n':
			flags |= ESCAPE_NULL;
			break;
		case 'o':
			flags |= ESCAPE_OCTAL;
			break;
		case 'p':
			flags |= ESCAPE_NP;
			break;
		case 's':
			flags |= ESCAPE_SPACE;
			break;
		default:
			found = false;
			break;
		}
	} while (found);

	if (!flags)
		flags = ESCAPE_ANY_NP;

	len = spec.field_width < 0 ? 1 : spec.field_width;

	/*
	 * string_escape_mem() writes as many characters as it can to
	 * the given buffer, and returns the total size of the output
	 * had the buffer been big enough.
	 */
	buf += string_escape_mem(addr, len, buf, buf < end ? end - buf : 0, flags, NULL);

	return buf;
}

__diag_push();
__diag_ignore(GCC, all, "-Wsuggest-attribute=format",
	      "Not a valid __printf() conversion candidate.");
static char *va_format(char *buf, char *end, struct va_format *va_fmt,
		       struct printf_spec spec)
{
	va_list va;

	if (check_pointer(&buf, end, va_fmt, spec))
		return buf;

	va_copy(va, *va_fmt->va);
	buf += vsnprintf(buf, end > buf ? end - buf : 0, va_fmt->fmt, va);
	va_end(va);

	return buf;
}
__diag_pop();

static noinline_for_stack
char *uuid_string(char *buf, char *end, const u8 *addr,
		  struct printf_spec spec, const char *fmt)
{
	char uuid[UUID_STRING_LEN + 1];
	char *p = uuid;
	int i;
	const u8 *index = uuid_index;
	bool uc = false;

	if (check_pointer(&buf, end, addr, spec))
		return buf;

	switch (*(++fmt)) {
	case 'L':
		uc = true;
		fallthrough;
	case 'l':
		index = guid_index;
		break;
	case 'B':
		uc = true;
		break;
	}

	for (i = 0; i < 16; i++) {
		if (uc)
			p = hex_byte_pack_upper(p, addr[index[i]]);
		else
			p = hex_byte_pack(p, addr[index[i]]);
		switch (i) {
		case 3:
		case 5:
		case 7:
		case 9:
			*p++ = '-';
			break;
		}
	}

	*p = 0;

	return string_nocheck(buf, end, uuid, spec);
}

static noinline_for_stack
char *netdev_bits(char *buf, char *end, const void *addr,
		  struct printf_spec spec,  const char *fmt)
{
	unsigned long long num;
	int size;

	if (check_pointer(&buf, end, addr, spec))
		return buf;

	switch (fmt[1]) {
	case 'F':
		num = *(const netdev_features_t *)addr;
		size = sizeof(netdev_features_t);
		break;
	default:
		return error_string(buf, end, "(%pN?)", spec);
	}

	return special_hex_number(buf, end, num, size);
}

static noinline_for_stack
char *fourcc_string(char *buf, char *end, const u32 *fourcc,
		    struct printf_spec spec, const char *fmt)
{
	char output[sizeof("0123 little-endian (0x01234567)")];
	char *p = output;
	unsigned int i;
	bool pixel_fmt = false;
	u32 orig, val;

	if (fmt[1] != 'c')
		return error_string(buf, end, "(%p4?)", spec);

	if (check_pointer(&buf, end, fourcc, spec))
		return buf;

	orig = get_unaligned(fourcc);
	switch (fmt[2]) {
	case 'h':
		if (fmt[3] == 'R')
			orig = swab32(orig);
		break;
	case 'l':
		orig = (__force u32)cpu_to_le32(orig);
		break;
	case 'b':
		orig = (__force u32)cpu_to_be32(orig);
		break;
	case 'c':
		/* Pixel formats are printed LSB-first */
		pixel_fmt = true;
		break;
	default:
		return error_string(buf, end, "(%p4?)", spec);
	}

	val = pixel_fmt ? swab32(orig & ~BIT(31)) : orig;

	for (i = 0; i < sizeof(u32); i++) {
		unsigned char c = val >> ((3 - i) * 8);

		/* Print non-control ASCII characters as-is, dot otherwise */
		*p++ = isascii(c) && isprint(c) ? c : '.';
	}

	if (pixel_fmt) {
		*p++ = ' ';
		strcpy(p, orig & BIT(31) ? "big-endian" : "little-endian");
		p += strlen(p);
	}

	*p++ = ' ';
	*p++ = '(';
	p = special_hex_number(p, output + sizeof(output) - 2, orig, sizeof(u32));
	*p++ = ')';
	*p = '\0';

	return string(buf, end, output, spec);
}

static noinline_for_stack
char *address_val(char *buf, char *end, const void *addr,
		  struct printf_spec spec, const char *fmt)
{
	unsigned long long num;
	int size;

	if (check_pointer(&buf, end, addr, spec))
		return buf;

	switch (fmt[1]) {
	case 'd':
		num = *(const dma_addr_t *)addr;
		size = sizeof(dma_addr_t);
		break;
	case 'p':
	default:
		num = *(const phys_addr_t *)addr;
		size = sizeof(phys_addr_t);
		break;
	}

	return special_hex_number(buf, end, num, size);
}

static noinline_for_stack
char *date_str(char *buf, char *end, const struct rtc_time *tm, bool r)
{
	int year = tm->tm_year + (r ? 0 : 1900);
	int mon = tm->tm_mon + (r ? 0 : 1);

	buf = number(buf, end, year, default_dec04_spec);
	if (buf < end)
		*buf = '-';
	buf++;

	buf = number(buf, end, mon, default_dec02_spec);
	if (buf < end)
		*buf = '-';
	buf++;

	return number(buf, end, tm->tm_mday, default_dec02_spec);
}

static noinline_for_stack
char *time_str(char *buf, char *end, const struct rtc_time *tm, bool r)
{
	buf = number(buf, end, tm->tm_hour, default_dec02_spec);
	if (buf < end)
		*buf = ':';
	buf++;

	buf = number(buf, end, tm->tm_min, default_dec02_spec);
	if (buf < end)
		*buf = ':';
	buf++;

	return number(buf, end, tm->tm_sec, default_dec02_spec);
}

static noinline_for_stack
char *rtc_str(char *buf, char *end, const struct rtc_time *tm,
	      struct printf_spec spec, const char *fmt)
{
	bool have_t = true, have_d = true;
	bool raw = false, iso8601_separator = true;
	bool found = true;
	int count = 2;

	if (check_pointer(&buf, end, tm, spec))
		return buf;

	switch (fmt[count]) {
	case 'd':
		have_t = false;
		count++;
		break;
	case 't':
		have_d = false;
		count++;
		break;
	}

	do {
		switch (fmt[count++]) {
		case 'r':
			raw = true;
			break;
		case 's':
			iso8601_separator = false;
			break;
		default:
			found = false;
			break;
		}
	} while (found);

	if (have_d)
		buf = date_str(buf, end, tm, raw);
	if (have_d && have_t) {
		if (buf < end)
			*buf = iso8601_separator ? 'T' : ' ';
		buf++;
	}
	if (have_t)
		buf = time_str(buf, end, tm, raw);

	return buf;
}

static noinline_for_stack
char *time64_str(char *buf, char *end, const time64_t time,
		 struct printf_spec spec, const char *fmt)
{
	struct rtc_time rtc_time;
	struct tm tm;

	time64_to_tm(time, 0, &tm);

	rtc_time.tm_sec = tm.tm_sec;
	rtc_time.tm_min = tm.tm_min;
	rtc_time.tm_hour = tm.tm_hour;
	rtc_time.tm_mday = tm.tm_mday;
	rtc_time.tm_mon = tm.tm_mon;
	rtc_time.tm_year = tm.tm_year;
	rtc_time.tm_wday = tm.tm_wday;
	rtc_time.tm_yday = tm.tm_yday;

	rtc_time.tm_isdst = 0;

	return rtc_str(buf, end, &rtc_time, spec, fmt);
}

static noinline_for_stack
char *time_and_date(char *buf, char *end, void *ptr, struct printf_spec spec,
		    const char *fmt)
{
	switch (fmt[1]) {
	case 'R':
		return rtc_str(buf, end, (const struct rtc_time *)ptr, spec, fmt);
	case 'T':
		return time64_str(buf, end, *(const time64_t *)ptr, spec, fmt);
	default:
		return error_string(buf, end, "(%pt?)", spec);
	}
}

static noinline_for_stack
char *clock(char *buf, char *end, struct clk *clk, struct printf_spec spec,
	    const char *fmt)
{
	if (!IS_ENABLED(CONFIG_HAVE_CLK))
		return error_string(buf, end, "(%pC?)", spec);

	if (check_pointer(&buf, end, clk, spec))
		return buf;

#ifdef CONFIG_COMMON_CLK
	return string(buf, end, __clk_get_name(clk), spec);
#else
	return ptr_to_id(buf, end, clk, spec);
#endif
}

static
char *format_flags(char *buf, char *end, unsigned long flags,
					const struct trace_print_flags *names)
{
	unsigned long mask;

	for ( ; flags && names->name; names++) {
		mask = names->mask;
		if ((flags & mask) != mask)
			continue;

		buf = string(buf, end, names->name, default_str_spec);

		flags &= ~mask;
		if (flags) {
			if (buf < end)
				*buf = '|';
			buf++;
		}
	}

	if (flags)
		buf = number(buf, end, flags, default_flag_spec);

	return buf;
}

struct page_flags_fields {
	int width;
	int shift;
	int mask;
	const struct printf_spec *spec;
	const char *name;
};

static const struct page_flags_fields pff[] = {
	{SECTIONS_WIDTH, SECTIONS_PGSHIFT, SECTIONS_MASK,
	 &default_dec_spec, "section"},
	{NODES_WIDTH, NODES_PGSHIFT, NODES_MASK,
	 &default_dec_spec, "node"},
	{ZONES_WIDTH, ZONES_PGSHIFT, ZONES_MASK,
	 &default_dec_spec, "zone"},
	{LAST_CPUPID_WIDTH, LAST_CPUPID_PGSHIFT, LAST_CPUPID_MASK,
	 &default_flag_spec, "lastcpupid"},
	{KASAN_TAG_WIDTH, KASAN_TAG_PGSHIFT, KASAN_TAG_MASK,
	 &default_flag_spec, "kasantag"},
};

static
char *format_page_flags(char *buf, char *end, unsigned long flags)
{
	unsigned long main_flags = flags & PAGEFLAGS_MASK;
	bool append = false;
	int i;

	buf = number(buf, end, flags, default_flag_spec);
	if (buf < end)
		*buf = '(';
	buf++;

	/* Page flags from the main area. */
	if (main_flags) {
		buf = format_flags(buf, end, main_flags, pageflag_names);
		append = true;
	}

	/* Page flags from the fields area */
	for (i = 0; i < ARRAY_SIZE(pff); i++) {
		/* Skip undefined fields. */
		if (!pff[i].width)
			continue;

		/* Format: Flag Name + '=' (equals sign) + Number + '|' (separator) */
		if (append) {
			if (buf < end)
				*buf = '|';
			buf++;
		}

		buf = string(buf, end, pff[i].name, default_str_spec);
		if (buf < end)
			*buf = '=';
		buf++;
		buf = number(buf, end, (flags >> pff[i].shift) & pff[i].mask,
			     *pff[i].spec);

		append = true;
	}
	if (buf < end)
		*buf = ')';
	buf++;

	return buf;
}

static noinline_for_stack
char *flags_string(char *buf, char *end, void *flags_ptr,
		   struct printf_spec spec, const char *fmt)
{
	unsigned long flags;
	const struct trace_print_flags *names;

	if (check_pointer(&buf, end, flags_ptr, spec))
		return buf;

	switch (fmt[1]) {
	case 'p':
		return format_page_flags(buf, end, *(unsigned long *)flags_ptr);
	case 'v':
		flags = *(unsigned long *)flags_ptr;
		names = vmaflag_names;
		break;
	case 'g':
		flags = (__force unsigned long)(*(gfp_t *)flags_ptr);
		names = gfpflag_names;
		break;
	default:
		return error_string(buf, end, "(%pG?)", spec);
	}

	return format_flags(buf, end, flags, names);
}

static noinline_for_stack
char *fwnode_full_name_string(struct fwnode_handle *fwnode, char *buf,
			      char *end)
{
	int depth;

	/* Loop starting from the root node to the current node. */
	for (depth = fwnode_count_parents(fwnode); depth >= 0; depth--) {
		/*
		 * Only get a reference for other nodes (i.e. parent nodes).
		 * fwnode refcount may be 0 here.
		 */
		struct fwnode_handle *__fwnode = depth ?
			fwnode_get_nth_parent(fwnode, depth) : fwnode;

		buf = string(buf, end, fwnode_get_name_prefix(__fwnode),
			     default_str_spec);
		buf = string(buf, end, fwnode_get_name(__fwnode),
			     default_str_spec);

		if (depth)
			fwnode_handle_put(__fwnode);
	}

	return buf;
}

static noinline_for_stack
char *device_node_string(char *buf, char *end, struct device_node *dn,
			 struct printf_spec spec, const char *fmt)
{
	char tbuf[sizeof("xxxx") + 1];
	const char *p;
	int ret;
	char *buf_start = buf;
	struct property *prop;
	bool has_mult, pass;

	struct printf_spec str_spec = spec;
	str_spec.field_width = -1;

	if (fmt[0] != 'F')
		return error_string(buf, end, "(%pO?)", spec);

	if (!IS_ENABLED(CONFIG_OF))
		return error_string(buf, end, "(%pOF?)", spec);

	if (check_pointer(&buf, end, dn, spec))
		return buf;

	/* simple case without anything any more format specifiers */
	fmt++;
	if (fmt[0] == '\0' || strcspn(fmt,"fnpPFcC") > 0)
		fmt = "f";

	for (pass = false; strspn(fmt,"fnpPFcC"); fmt++, pass = true) {
		int precision;
		if (pass) {
			if (buf < end)
				*buf = ':';
			buf++;
		}

		switch (*fmt) {
		case 'f':	/* full_name */
			buf = fwnode_full_name_string(of_fwnode_handle(dn), buf,
						      end);
			break;
		case 'n':	/* name */
			p = fwnode_get_name(of_fwnode_handle(dn));
			precision = str_spec.precision;
			str_spec.precision = strchrnul(p, '@') - p;
			buf = string(buf, end, p, str_spec);
			str_spec.precision = precision;
			break;
		case 'p':	/* phandle */
			buf = number(buf, end, (unsigned int)dn->phandle, default_dec_spec);
			break;
		case 'P':	/* path-spec */
			p = fwnode_get_name(of_fwnode_handle(dn));
			if (!p[1])
				p = "/";
			buf = string(buf, end, p, str_spec);
			break;
		case 'F':	/* flags */
			tbuf[0] = of_node_check_flag(dn, OF_DYNAMIC) ? 'D' : '-';
			tbuf[1] = of_node_check_flag(dn, OF_DETACHED) ? 'd' : '-';
			tbuf[2] = of_node_check_flag(dn, OF_POPULATED) ? 'P' : '-';
			tbuf[3] = of_node_check_flag(dn, OF_POPULATED_BUS) ? 'B' : '-';
			tbuf[4] = 0;
			buf = string_nocheck(buf, end, tbuf, str_spec);
			break;
		case 'c':	/* major compatible string */
			ret = of_property_read_string(dn, "compatible", &p);
			if (!ret)
				buf = string(buf, end, p, str_spec);
			break;
		case 'C':	/* full compatible string */
			has_mult = false;
			of_property_for_each_string(dn, "compatible", prop, p) {
				if (has_mult)
					buf = string_nocheck(buf, end, ",", str_spec);
				buf = string_nocheck(buf, end, "\"", str_spec);
				buf = string(buf, end, p, str_spec);
				buf = string_nocheck(buf, end, "\"", str_spec);

				has_mult = true;
			}
			break;
		default:
			break;
		}
	}

	return widen_string(buf, buf - buf_start, end, spec);
}

static noinline_for_stack
char *fwnode_string(char *buf, char *end, struct fwnode_handle *fwnode,
		    struct printf_spec spec, const char *fmt)
{
	struct printf_spec str_spec = spec;
	char *buf_start = buf;

	str_spec.field_width = -1;

	if (*fmt != 'w')
		return error_string(buf, end, "(%pf?)", spec);

	if (check_pointer(&buf, end, fwnode, spec))
		return buf;

	fmt++;

	switch (*fmt) {
	case 'P':	/* name */
		buf = string(buf, end, fwnode_get_name(fwnode), str_spec);
		break;
	case 'f':	/* full_name */
	default:
		buf = fwnode_full_name_string(fwnode, buf, end);
		break;
	}

	return widen_string(buf, buf - buf_start, end, spec);
}

static noinline_for_stack
char *resource_or_range(const char *fmt, char *buf, char *end, void *ptr,
			struct printf_spec spec)
{
	if (*fmt == 'r' && fmt[1] == 'a')
		return range_string(buf, end, ptr, spec, fmt);
	return resource_string(buf, end, ptr, spec, fmt);
}

void __init hash_pointers_finalize(bool slub_debug)
{
	switch (hash_pointers_mode) {
	case HASH_PTR_ALWAYS:
		no_hash_pointers = false;
		break;
	case HASH_PTR_NEVER:
		no_hash_pointers = true;
		break;
	case HASH_PTR_AUTO:
	default:
		no_hash_pointers = slub_debug;
		break;
	}

	if (!no_hash_pointers)
		return;

	pr_warn("**********************************************************\n");
	pr_warn("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** This system shows unhashed kernel memory addresses   **\n");
	pr_warn("** via the console, logs, and other interfaces. This    **\n");
	pr_warn("** might reduce the security of your system.            **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** If you see this message and you are not debugging    **\n");
	pr_warn("** the kernel, report this immediately to your system   **\n");
	pr_warn("** administrator!                                       **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** Use hash_pointers=always to force this mode off      **\n");
	pr_warn("**                                                      **\n");
	pr_warn("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_warn("**********************************************************\n");
}

static int __init hash_pointers_mode_parse(char *str)
{
	if (!str) {
		pr_warn("Hash pointers mode empty; falling back to auto.\n");
		hash_pointers_mode = HASH_PTR_AUTO;
	} else if (strncmp(str, "auto", 4) == 0)   {
		pr_info("Hash pointers mode set to auto.\n");
		hash_pointers_mode = HASH_PTR_AUTO;
	} else if (strncmp(str, "never", 5) == 0) {
		pr_info("Hash pointers mode set to never.\n");
		hash_pointers_mode = HASH_PTR_NEVER;
	} else if (strncmp(str, "always", 6) == 0) {
		pr_info("Hash pointers mode set to always.\n");
		hash_pointers_mode = HASH_PTR_ALWAYS;
	} else {
		pr_warn("Unknown hash_pointers mode '%s' specified; assuming auto.\n", str);
		hash_pointers_mode = HASH_PTR_AUTO;
	}

	return 0;
}
early_param("hash_pointers", hash_pointers_mode_parse);

static int __init no_hash_pointers_enable(char *str)
{
	return hash_pointers_mode_parse("never");
}
early_param("no_hash_pointers", no_hash_pointers_enable);

/*
 * Show a '%p' thing.  A kernel extension is that the '%p' is followed
 * by an extra set of alphanumeric characters that are extended format
 * specifiers.
 *
 * Please update scripts/checkpatch.pl when adding/removing conversion
 * characters.  (Search for "check for vsprintf extension").
 *
 * Right now we handle:
 *
 * - 'S' For symbolic direct pointers (or function descriptors) with offset
 * - 's' For symbolic direct pointers (or function descriptors) without offset
 * - '[Ss]R' as above with __builtin_extract_return_addr() translation
 * - 'S[R]b' as above with module build ID (for use in backtraces)
 * - '[Ff]' %pf and %pF were obsoleted and later removed in favor of
 *	    %ps and %pS. Be careful when re-using these specifiers.
 * - 'B' For backtraced symbolic direct pointers with offset
 * - 'Bb' as above with module build ID (for use in backtraces)
 * - 'R' For decoded struct resource, e.g., [mem 0x0-0x1f 64bit pref]
 * - 'r' For raw struct resource, e.g., [mem 0x0-0x1f flags 0x201]
 * - 'ra' For struct ranges, e.g., [range 0x0000000000000000 - 0x00000000000000ff]
 * - 'b[l]' For a bitmap, the number of bits is determined by the field
 *       width which must be explicitly specified either as part of the
 *       format string '%32b[l]' or through '%*b[l]', [l] selects
 *       range-list format instead of hex format
 * - 'M' For a 6-byte MAC address, it prints the address in the
 *       usual colon-separated hex notation
 * - 'm' For a 6-byte MAC address, it prints the hex address without colons
 * - 'MF' For a 6-byte MAC FDDI address, it prints the address
 *       with a dash-separated hex notation
 * - '[mM]R' For a 6-byte MAC address, Reverse order (Bluetooth)
 * - 'I' [46] for IPv4/IPv6 addresses printed in the usual way
 *       IPv4 uses dot-separated decimal without leading 0's (1.2.3.4)
 *       IPv6 uses colon separated network-order 16 bit hex with leading 0's
 *       [S][pfs]
 *       Generic IPv4/IPv6 address (struct sockaddr *) that falls back to
 *       [4] or [6] and is able to print port [p], flowinfo [f], scope [s]
 * - 'i' [46] for 'raw' IPv4/IPv6 addresses
 *       IPv6 omits the colons (01020304...0f)
 *       IPv4 uses dot-separated decimal with leading 0's (010.123.045.006)
 *       [S][pfs]
 *       Generic IPv4/IPv6 address (struct sockaddr *) that falls back to
 *       [4] or [6] and is able to print port [p], flowinfo [f], scope [s]
 * - '[Ii][4S][hnbl]' IPv4 addresses in host, network, big or little endian order
 * - 'I[6S]c' for IPv6 addresses printed as specified by
 *       https://tools.ietf.org/html/rfc5952
 * - 'E[achnops]' For an escaped buffer, where rules are defined by combination
 *                of the following flags (see string_escape_mem() for the
 *                details):
 *                  a - ESCAPE_ANY
 *                  c - ESCAPE_SPECIAL
 *                  h - ESCAPE_HEX
 *                  n - ESCAPE_NULL
 *                  o - ESCAPE_OCTAL
 *                  p - ESCAPE_NP
 *                  s - ESCAPE_SPACE
 *                By default ESCAPE_ANY_NP is used.
 * - 'U' For a 16 byte UUID/GUID, it prints the UUID/GUID in the form
 *       "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 *       Options for %pU are:
 *         b big endian lower case hex (default)
 *         B big endian UPPER case hex
 *         l little endian lower case hex
 *         L little endian UPPER case hex
 *           big endian output byte order is:
 *             [0][1][2][3]-[4][5]-[6][7]-[8][9]-[10][11][12][13][14][15]
 *           little endian output byte order is:
 *             [3][2][1][0]-[5][4]-[7][6]-[8][9]-[10][11][12][13][14][15]
 * - 'V' For a struct va_format which contains a format string * and va_list *,
 *       call vsnprintf(->format, *->va_list).
 *       Implements a "recursive vsnprintf".
 *       Do not use this feature without some mechanism to verify the
 *       correctness of the format string and va_list arguments.
 * - 'K' For a kernel pointer that should be hidden from unprivileged users.
 *       Use only for procfs, sysfs and similar files, not printk(); please
 *       read the documentation (path below) first.
 * - 'NF' For a netdev_features_t
 * - '4cc' V4L2 or DRM FourCC code, with endianness and raw numerical value.
 * - '4c[h[R]lb]' For generic FourCC code with raw numerical value. Both are
 *	 displayed in the big-endian format. This is the opposite of V4L2 or
 *	 DRM FourCCs.
 *	 The additional specifiers define what endianness is used to load
 *	 the stored bytes. The data might be interpreted using the host,
 *	 reversed host byte order, little-endian, or big-endian.
 * - 'h[CDN]' For a variable-length buffer, it prints it as a hex string with
 *            a certain separator (' ' by default):
 *              C colon
 *              D dash
 *              N no separator
 *            The maximum supported length is 64 bytes of the input. Consider
 *            to use print_hex_dump() for the larger input.
 * - 'a[pd]' For address types [p] phys_addr_t, [d] dma_addr_t and derivatives
 *           (default assumed to be phys_addr_t, passed by reference)
 * - 'd[234]' For a dentry name (optionally 2-4 last components)
 * - 'D[234]' Same as 'd' but for a struct file
 * - 'g' For block_device name (gendisk + partition number)
 * - 't[RT][dt][r][s]' For time and date as represented by:
 *      R    struct rtc_time
 *      T    time64_t
 * - 'C' For a clock, it prints the name (Common Clock Framework) or address
 *       (legacy clock framework) of the clock
 * - 'G' For flags to be printed as a collection of symbolic strings that would
 *       construct the specific value. Supported flags given by option:
 *       p page flags (see struct page) given as pointer to unsigned long
 *       g gfp flags (GFP_* and __GFP_*) given as pointer to gfp_t
 *       v vma flags (VM_*) given as pointer to unsigned long
 * - 'OF[fnpPcCF]'  For a device tree object
 *                  Without any optional arguments prints the full_name
 *                  f device node full_name
 *                  n device node name
 *                  p device node phandle
 *                  P device node path spec (name + @unit)
 *                  F device node flags
 *                  c major compatible string
 *                  C full compatible string
 * - 'fw[fP]'	For a firmware node (struct fwnode_handle) pointer
 *		Without an option prints the full name of the node
 *		f full name
 *		P node name, including a possible unit address
 * - 'x' For printing the address unmodified. Equivalent to "%lx".
 *       Please read the documentation (path below) before using!
 * - '[ku]s' For a BPF/tracing related format specifier, e.g. used out of
 *           bpf_trace_printk() where [ku] prefix specifies either kernel (k)
 *           or user (u) memory to probe, and:
 *              s a string, equivalent to "%s" on direct vsnprintf() use
 *
 * ** When making changes please also update:
 *	Documentation/core-api/printk-formats.rst
 *
 * Note: The default behaviour (unadorned %p) is to hash the address,
 * rendering it useful as a unique identifier.
 *
 * There is also a '%pA' format specifier, but it is only intended to be used
 * from Rust code to format core::fmt::Arguments. Do *not* use it from C.
 * See rust/kernel/print.rs for details.
 */
static noinline_for_stack
char *pointer(const char *fmt, char *buf, char *end, void *ptr,
	      struct printf_spec spec)
{
	switch (*fmt) {
	case 'S':
	case 's':
		ptr = dereference_symbol_descriptor(ptr);
		fallthrough;
	case 'B':
		return symbol_string(buf, end, ptr, spec, fmt);
	case 'R':
	case 'r':
		return resource_or_range(fmt, buf, end, ptr, spec);
	case 'h':
		return hex_string(buf, end, ptr, spec, fmt);
	case 'b':
		switch (fmt[1]) {
		case 'l':
			return bitmap_list_string(buf, end, ptr, spec, fmt);
		default:
			return bitmap_string(buf, end, ptr, spec, fmt);
		}
	case 'M':			/* Colon separated: 00:01:02:03:04:05 */
	case 'm':			/* Contiguous: 000102030405 */
					/* [mM]F (FDDI) */
					/* [mM]R (Reverse order; Bluetooth) */
		return mac_address_string(buf, end, ptr, spec, fmt);
	case 'I':			/* Formatted IP supported
					 * 4:	1.2.3.4
					 * 6:	0001:0203:...:0708
					 * 6c:	1::708 or 1::1.2.3.4
					 */
	case 'i':			/* Contiguous:
					 * 4:	001.002.003.004
					 * 6:   000102...0f
					 */
		return ip_addr_string(buf, end, ptr, spec, fmt);
	case 'E':
		return escaped_string(buf, end, ptr, spec, fmt);
	case 'U':
		return uuid_string(buf, end, ptr, spec, fmt);
	case 'V':
		return va_format(buf, end, ptr, spec);
	case 'K':
		return restricted_pointer(buf, end, ptr, spec);
	case 'N':
		return netdev_bits(buf, end, ptr, spec, fmt);
	case '4':
		return fourcc_string(buf, end, ptr, spec, fmt);
	case 'a':
		return address_val(buf, end, ptr, spec, fmt);
	case 'd':
		return dentry_name(buf, end, ptr, spec, fmt);
	case 't':
		return time_and_date(buf, end, ptr, spec, fmt);
	case 'C':
		return clock(buf, end, ptr, spec, fmt);
	case 'D':
		return file_dentry_name(buf, end, ptr, spec, fmt);
#ifdef CONFIG_BLOCK
	case 'g':
		return bdev_name(buf, end, ptr, spec, fmt);
#endif

	case 'G':
		return flags_string(buf, end, ptr, spec, fmt);
	case 'O':
		return device_node_string(buf, end, ptr, spec, fmt + 1);
	case 'f':
		return fwnode_string(buf, end, ptr, spec, fmt + 1);
	case 'A':
		if (!IS_ENABLED(CONFIG_RUST)) {
			WARN_ONCE(1, "Please remove %%pA from non-Rust code\n");
			return error_string(buf, end, "(%pA?)", spec);
		}
		return rust_fmt_argument(buf, end, ptr);
	case 'x':
		return pointer_string(buf, end, ptr, spec);
	case 'e':
		/* %pe with a non-ERR_PTR gets treated as plain %p */
		if (!IS_ERR(ptr))
			return default_pointer(buf, end, ptr, spec);
		return err_ptr(buf, end, ptr, spec);
	case 'u':
	case 'k':
		switch (fmt[1]) {
		case 's':
			return string(buf, end, ptr, spec);
		default:
			return error_string(buf, end, "(einval)", spec);
		}
	default:
		return default_pointer(buf, end, ptr, spec);
	}
}

struct fmt {
	const char *str;
	unsigned char state;	// enum format_state
	unsigned char size;	// size of numbers
};

#define SPEC_CHAR(x, flag) [(x)-32] = flag
static unsigned char spec_flag(unsigned char c)
{
	static const unsigned char spec_flag_array[] = {
		SPEC_CHAR(' ', SPACE),
		SPEC_CHAR('#', SPECIAL),
		SPEC_CHAR('+', PLUS),
		SPEC_CHAR('-', LEFT),
		SPEC_CHAR('0', ZEROPAD),
	};
	c -= 32;
	return (c < sizeof(spec_flag_array)) ? spec_flag_array[c] : 0;
}

/*
 * Helper function to decode printf style format.
 * Each call decode a token from the format and return the
 * number of characters read (or likely the delta where it wants
 * to go on the next call).
 * The decoded token is returned through the parameters
 *
 * 'h', 'l', or 'L' for integer fields
 * 'z' support added 23/7/1999 S.H.
 * 'z' changed to 'Z' --davidm 1/25/99
 * 'Z' changed to 'z' --adobriyan 2017-01-25
 * 't' added for ptrdiff_t
 *
 * @fmt: the format string
 * @type of the token returned
 * @flags: various flags such as +, -, # tokens..
 * @field_width: overwritten width
 * @base: base of the number (octal, hex, ...)
 * @precision: precision of a number
 * @qualifier: qualifier of a number (long, size_t, ...)
 */
static noinline_for_stack
struct fmt format_decode(struct fmt fmt, struct printf_spec *spec)
{
	const char *start = fmt.str;
	char flag;

	/* we finished early by reading the field width */
	if (unlikely(fmt.state == FORMAT_STATE_WIDTH)) {
		if (spec->field_width < 0) {
			spec->field_width = -spec->field_width;
			spec->flags |= LEFT;
		}
		fmt.state = FORMAT_STATE_NONE;
		goto precision;
	}

	/* we finished early by reading the precision */
	if (unlikely(fmt.state == FORMAT_STATE_PRECISION)) {
		if (spec->precision < 0)
			spec->precision = 0;

		fmt.state = FORMAT_STATE_NONE;
		goto qualifier;
	}

	/* By default */
	fmt.state = FORMAT_STATE_NONE;

	for (; *fmt.str ; fmt.str++) {
		if (*fmt.str == '%')
			break;
	}

	/* Return the current non-format string */
	if (fmt.str != start || !*fmt.str)
		return fmt;

	/* Process flags. This also skips the first '%' */
	spec->flags = 0;
	do {
		/* this also skips first '%' */
		flag = spec_flag(*++fmt.str);
		spec->flags |= flag;
	} while (flag);

	/* get field width */
	spec->field_width = -1;

	if (isdigit(*fmt.str))
		spec->field_width = skip_atoi(&fmt.str);
	else if (unlikely(*fmt.str == '*')) {
		/* it's the next argument */
		fmt.state = FORMAT_STATE_WIDTH;
		fmt.str++;
		return fmt;
	}

precision:
	/* get the precision */
	spec->precision = -1;
	if (unlikely(*fmt.str == '.')) {
		fmt.str++;
		if (isdigit(*fmt.str)) {
			spec->precision = skip_atoi(&fmt.str);
			if (spec->precision < 0)
				spec->precision = 0;
		} else if (*fmt.str == '*') {
			/* it's the next argument */
			fmt.state = FORMAT_STATE_PRECISION;
			fmt.str++;
			return fmt;
		}
	}

qualifier:
	/* Set up default numeric format */
	spec->base = 10;
	fmt.state = FORMAT_STATE_NUM;
	fmt.size = sizeof(int);
	static const struct format_state {
		unsigned char state;
		unsigned char size;
		unsigned char flags_or_double_size;
		unsigned char base;
	} lookup_state[256] = {
		// Length
		['l'] = { 0, sizeof(long), sizeof(long long) },
		['L'] = { 0, sizeof(long long) },
		['h'] = { 0, sizeof(short), sizeof(char) },
		['H'] = { 0, sizeof(char) },	// Questionable historical
		['z'] = { 0, sizeof(size_t) },
		['t'] = { 0, sizeof(ptrdiff_t) },

		// Non-numeric formats
		['c'] = { FORMAT_STATE_CHAR },
		['s'] = { FORMAT_STATE_STR },
		['p'] = { FORMAT_STATE_PTR },
		['%'] = { FORMAT_STATE_PERCENT_CHAR },

		// Numerics
		['o'] = { FORMAT_STATE_NUM, 0, 0, 8 },
		['x'] = { FORMAT_STATE_NUM, 0, SMALL, 16 },
		['X'] = { FORMAT_STATE_NUM, 0, 0, 16 },
		['d'] = { FORMAT_STATE_NUM, 0, SIGN, 10 },
		['i'] = { FORMAT_STATE_NUM, 0, SIGN, 10 },
		['u'] = { FORMAT_STATE_NUM, 0, 0, 10, },

		/*
		 * Since %n poses a greater security risk than
		 * utility, treat it as any other invalid or
		 * unsupported format specifier.
		 */
	};

	const struct format_state *p = lookup_state + (u8)*fmt.str;
	if (p->size) {
		fmt.size = p->size;
		if (p->flags_or_double_size && fmt.str[0] == fmt.str[1]) {
			fmt.size = p->flags_or_double_size;
			fmt.str++;
		}
		fmt.str++;
		p = lookup_state + *fmt.str;
	}
	if (p->state) {
		if (p->base)
			spec->base = p->base;
		spec->flags |= p->flags_or_double_size;
		fmt.state = p->state;
		fmt.str++;
		return fmt;
	}

	WARN_ONCE(1, "Please remove unsupported %%%c in format string\n", *fmt.str);
	fmt.state = FORMAT_STATE_INVALID;
	return fmt;
}

static void
set_field_width(struct printf_spec *spec, int width)
{
	spec->field_width = width;
	if (WARN_ONCE(spec->field_width != width, "field width %d too large", width)) {
		spec->field_width = clamp(width, -FIELD_WIDTH_MAX, FIELD_WIDTH_MAX);
	}
}

static void
set_precision(struct printf_spec *spec, int prec)
{
	spec->precision = prec;
	if (WARN_ONCE(spec->precision != prec, "precision %d too large", prec)) {
		spec->precision = clamp(prec, 0, PRECISION_MAX);
	}
}

/*
 * Turn a 1/2/4-byte value into a 64-bit one for printing: truncate
 * as necessary and deal with signedness.
 *
 * 'size' is the size of the value in bytes.
 */
static unsigned long long convert_num_spec(unsigned int val, int size, struct printf_spec spec)
{
	unsigned int shift = 32 - size*8;

	val <<= shift;
	if (!(spec.flags & SIGN))
		return val >> shift;
	return (int)val >> shift;
}

/**
 * vsnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt_str: The format string to use
 * @args: Arguments for the format string
 *
 * This function generally follows C99 vsnprintf, but has some
 * extensions and a few limitations:
 *
 *  - ``%n`` is unsupported
 *  - ``%p*`` is handled by pointer()
 *
 * See pointer() or Documentation/core-api/printk-formats.rst for more
 * extensive description.
 *
 * **Please update the documentation in both places when making changes**
 *
 * The return value is the number of characters which would
 * be generated for the given input, excluding the trailing
 * '\0', as per ISO C99. If you want to have the exact
 * number of characters written into @buf as return value
 * (not including the trailing '\0'), use vscnprintf(). If the
 * return is greater than or equal to @size, the resulting
 * string is truncated.
 *
 * If you're not already dealing with a va_list consider using snprintf().
 */
int vsnprintf(char *buf, size_t size, const char *fmt_str, va_list args)
{
	char *str, *end;
	struct printf_spec spec = {0};
	struct fmt fmt = {
		.str = fmt_str,
		.state = FORMAT_STATE_NONE,
	};

	/* Reject out-of-range values early.  Large positive sizes are
	   used for unknown buffer sizes. */
	if (WARN_ON_ONCE(size > INT_MAX))
		return 0;

	str = buf;
	end = buf + size;

	/* Make sure end is always >= buf */
	if (end < buf) {
		end = ((void *)-1);
		size = end - buf;
	}

	while (*fmt.str) {
		const char *old_fmt = fmt.str;

		fmt = format_decode(fmt, &spec);

		switch (fmt.state) {
		case FORMAT_STATE_NONE: {
			int read = fmt.str - old_fmt;
			if (str < end) {
				int copy = read;
				if (copy > end - str)
					copy = end - str;
				memcpy(str, old_fmt, copy);
			}
			str += read;
			continue;
		}

		case FORMAT_STATE_NUM: {
			unsigned long long num;
			if (fmt.size <= sizeof(int))
				num = convert_num_spec(va_arg(args, int), fmt.size, spec);
			else
				num = va_arg(args, long long);
			str = number(str, end, num, spec);
			continue;
		}

		case FORMAT_STATE_WIDTH:
			set_field_width(&spec, va_arg(args, int));
			continue;

		case FORMAT_STATE_PRECISION:
			set_precision(&spec, va_arg(args, int));
			continue;

		case FORMAT_STATE_CHAR: {
			char c;

			if (!(spec.flags & LEFT)) {
				while (--spec.field_width > 0) {
					if (str < end)
						*str = ' ';
					++str;

				}
			}
			c = (unsigned char) va_arg(args, int);
			if (str < end)
				*str = c;
			++str;
			while (--spec.field_width > 0) {
				if (str < end)
					*str = ' ';
				++str;
			}
			continue;
		}

		case FORMAT_STATE_STR:
			str = string(str, end, va_arg(args, char *), spec);
			continue;

		case FORMAT_STATE_PTR:
			str = pointer(fmt.str, str, end, va_arg(args, void *),
				      spec);
			while (isalnum(*fmt.str))
				fmt.str++;
			continue;

		case FORMAT_STATE_PERCENT_CHAR:
			if (str < end)
				*str = '%';
			++str;
			continue;

		default:
			/*
			 * Presumably the arguments passed gcc's type
			 * checking, but there is no safe or sane way
			 * for us to continue parsing the format and
			 * fetching from the va_list; the remaining
			 * specifiers and arguments would be out of
			 * sync.
			 */
			goto out;
		}
	}

out:
	if (size > 0) {
		if (str < end)
			*str = '\0';
		else
			end[-1] = '\0';
	}

	/* the trailing null byte doesn't count towards the total */
	return str-buf;

}
EXPORT_SYMBOL(vsnprintf);

/**
 * vscnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The return value is the number of characters which have been written into
 * the @buf not including the trailing '\0'. If @size is == 0 the function
 * returns 0.
 *
 * If you're not already dealing with a va_list consider using scnprintf().
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int i;

	if (unlikely(!size))
		return 0;

	i = vsnprintf(buf, size, fmt, args);

	if (likely(i < size))
		return i;

	return size - 1;
}
EXPORT_SYMBOL(vscnprintf);

/**
 * snprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters which would be
 * generated for the given input, excluding the trailing null,
 * as per ISO C99.  If the return is greater than or equal to
 * @size, the resulting string is truncated.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int snprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(snprintf);

/**
 * scnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters written into @buf not including
 * the trailing '\0'. If @size is == 0 the function returns 0.
 */

int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(scnprintf);

/**
 * vsprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use vsnprintf() or vscnprintf() in order to avoid
 * buffer overflows.
 *
 * If you're not already dealing with a va_list consider using sprintf().
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vsprintf(char *buf, const char *fmt, va_list args)
{
	return vsnprintf(buf, INT_MAX, fmt, args);
}
EXPORT_SYMBOL(vsprintf);

/**
 * sprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use snprintf() or scnprintf() in order to avoid
 * buffer overflows.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int sprintf(char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, INT_MAX, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sprintf);

#ifdef CONFIG_BINARY_PRINTF
/*
 * bprintf service:
 * vbin_printf() - VA arguments to binary data
 * bstr_printf() - Binary data to text string
 */

/**
 * vbin_printf - Parse a format string and place args' binary value in a buffer
 * @bin_buf: The buffer to place args' binary value
 * @size: The size of the buffer(by words(32bits), not characters)
 * @fmt_str: The format string to use
 * @args: Arguments for the format string
 *
 * The format follows C99 vsnprintf, except %n is ignored, and its argument
 * is skipped.
 *
 * The return value is the number of words(32bits) which would be generated for
 * the given input.
 *
 * NOTE:
 * If the return value is greater than @size, the resulting bin_buf is NOT
 * valid for bstr_printf().
 */
int vbin_printf(u32 *bin_buf, size_t size, const char *fmt_str, va_list args)
{
	struct fmt fmt = {
		.str = fmt_str,
		.state = FORMAT_STATE_NONE,
	};
	struct printf_spec spec = {0};
	char *str, *end;
	int width;

	str = (char *)bin_buf;
	end = (char *)(bin_buf + size);

#define save_arg(type)							\
({									\
	unsigned long long value;					\
	if (sizeof(type) == 8) {					\
		unsigned long long val8;				\
		str = PTR_ALIGN(str, sizeof(u32));			\
		val8 = va_arg(args, unsigned long long);		\
		if (str + sizeof(type) <= end) {			\
			*(u32 *)str = *(u32 *)&val8;			\
			*(u32 *)(str + 4) = *((u32 *)&val8 + 1);	\
		}							\
		value = val8;						\
	} else {							\
		unsigned int val4;					\
		str = PTR_ALIGN(str, sizeof(type));			\
		val4 = va_arg(args, int);				\
		if (str + sizeof(type) <= end)				\
			*(typeof(type) *)str = (type)(long)val4;	\
		value = (unsigned long long)val4;			\
	}								\
	str += sizeof(type);						\
	value;								\
})

	while (*fmt.str) {
		fmt = format_decode(fmt, &spec);

		switch (fmt.state) {
		case FORMAT_STATE_NONE:
		case FORMAT_STATE_PERCENT_CHAR:
			break;
		case FORMAT_STATE_INVALID:
			goto out;

		case FORMAT_STATE_WIDTH:
		case FORMAT_STATE_PRECISION:
			width = (int)save_arg(int);
			/* Pointers may require the width */
			if (*fmt.str == 'p')
				set_field_width(&spec, width);
			break;

		case FORMAT_STATE_CHAR:
			save_arg(char);
			break;

		case FORMAT_STATE_STR: {
			const char *save_str = va_arg(args, char *);
			const char *err_msg;
			size_t len;

			err_msg = check_pointer_msg(save_str);
			if (err_msg)
				save_str = err_msg;

			len = strlen(save_str) + 1;
			if (str + len < end)
				memcpy(str, save_str, len);
			str += len;
			break;
		}

		case FORMAT_STATE_PTR:
			/* Dereferenced pointers must be done now */
			switch (*fmt.str) {
			/* Dereference of functions is still OK */
			case 'S':
			case 's':
			case 'x':
			case 'K':
			case 'e':
				save_arg(void *);
				break;
			default:
				if (!isalnum(*fmt.str)) {
					save_arg(void *);
					break;
				}
				str = pointer(fmt.str, str, end, va_arg(args, void *),
					      spec);
				if (str + 1 < end)
					*str++ = '\0';
				else
					end[-1] = '\0'; /* Must be nul terminated */
			}
			/* skip all alphanumeric pointer suffixes */
			while (isalnum(*fmt.str))
				fmt.str++;
			break;

		case FORMAT_STATE_NUM:
			if (fmt.size > sizeof(int)) {
				save_arg(long long);
			} else {
				save_arg(int);
			}
		}
	}

out:
	return (u32 *)(PTR_ALIGN(str, sizeof(u32))) - bin_buf;
#undef save_arg
}
EXPORT_SYMBOL_GPL(vbin_printf);

/**
 * bstr_printf - Format a string from binary arguments and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt_str: The format string to use
 * @bin_buf: Binary arguments for the format string
 *
 * This function like C99 vsnprintf, but the difference is that vsnprintf gets
 * arguments from stack, and bstr_printf gets arguments from @bin_buf which is
 * a binary buffer that generated by vbin_printf.
 *
 * The format follows C99 vsnprintf, but has some extensions:
 *  see vsnprintf comment for details.
 *
 * The return value is the number of characters which would
 * be generated for the given input, excluding the trailing
 * '\0', as per ISO C99. If you want to have the exact
 * number of characters written into @buf as return value
 * (not including the trailing '\0'), use vscnprintf(). If the
 * return is greater than or equal to @size, the resulting
 * string is truncated.
 */
int bstr_printf(char *buf, size_t size, const char *fmt_str, const u32 *bin_buf)
{
	struct fmt fmt = {
		.str = fmt_str,
		.state = FORMAT_STATE_NONE,
	};
	struct printf_spec spec = {0};
	char *str, *end;
	const char *args = (const char *)bin_buf;

	if (WARN_ON_ONCE(size > INT_MAX))
		return 0;

	str = buf;
	end = buf + size;

#define get_arg(type)							\
({									\
	typeof(type) value;						\
	if (sizeof(type) == 8) {					\
		args = PTR_ALIGN(args, sizeof(u32));			\
		*(u32 *)&value = *(u32 *)args;				\
		*((u32 *)&value + 1) = *(u32 *)(args + 4);		\
	} else {							\
		args = PTR_ALIGN(args, sizeof(type));			\
		value = *(typeof(type) *)args;				\
	}								\
	args += sizeof(type);						\
	value;								\
})

	/* Make sure end is always >= buf */
	if (end < buf) {
		end = ((void *)-1);
		size = end - buf;
	}

	while (*fmt.str) {
		const char *old_fmt = fmt.str;
		unsigned long long num;

		fmt = format_decode(fmt, &spec);
		switch (fmt.state) {
		case FORMAT_STATE_NONE: {
			int read = fmt.str - old_fmt;
			if (str < end) {
				int copy = read;
				if (copy > end - str)
					copy = end - str;
				memcpy(str, old_fmt, copy);
			}
			str += read;
			continue;
		}

		case FORMAT_STATE_WIDTH:
			set_field_width(&spec, get_arg(int));
			continue;

		case FORMAT_STATE_PRECISION:
			set_precision(&spec, get_arg(int));
			continue;

		case FORMAT_STATE_CHAR: {
			char c;

			if (!(spec.flags & LEFT)) {
				while (--spec.field_width > 0) {
					if (str < end)
						*str = ' ';
					++str;
				}
			}
			c = (unsigned char) get_arg(char);
			if (str < end)
				*str = c;
			++str;
			while (--spec.field_width > 0) {
				if (str < end)
					*str = ' ';
				++str;
			}
			continue;
		}

		case FORMAT_STATE_STR: {
			const char *str_arg = args;
			args += strlen(str_arg) + 1;
			str = string(str, end, (char *)str_arg, spec);
			continue;
		}

		case FORMAT_STATE_PTR: {
			bool process = false;
			int copy, len;
			/* Non function dereferences were already done */
			switch (*fmt.str) {
			case 'S':
			case 's':
			case 'x':
			case 'K':
			case 'e':
				process = true;
				break;
			default:
				if (!isalnum(*fmt.str)) {
					process = true;
					break;
				}
				/* Pointer dereference was already processed */
				if (str < end) {
					len = copy = strlen(args);
					if (copy > end - str)
						copy = end - str;
					memcpy(str, args, copy);
					str += len;
					args += len + 1;
				}
			}
			if (process)
				str = pointer(fmt.str, str, end, get_arg(void *), spec);

			while (isalnum(*fmt.str))
				fmt.str++;
			continue;
		}

		case FORMAT_STATE_PERCENT_CHAR:
			if (str < end)
				*str = '%';
			++str;
			continue;

		case FORMAT_STATE_INVALID:
			goto out;

		case FORMAT_STATE_NUM:
			if (fmt.size > sizeof(int)) {
				num = get_arg(long long);
			} else {
				num = convert_num_spec(get_arg(int), fmt.size, spec);
			}
			str = number(str, end, num, spec);
			continue;
		}
	} /* while(*fmt.str) */

out:
	if (size > 0) {
		if (str < end)
			*str = '\0';
		else
			end[-1] = '\0';
	}

#undef get_arg

	/* the trailing null byte doesn't count towards the total */
	return str - buf;
}
EXPORT_SYMBOL_GPL(bstr_printf);

#endif /* CONFIG_BINARY_PRINTF */

/**
 * vsscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	format of buffer
 * @args:	arguments
 */
int vsscanf(const char *buf, const char *fmt, va_list args)
{
	const char *str = buf;
	char *next;
	char digit;
	int num = 0;
	u8 qualifier;
	unsigned int base;
	union {
		long long s;
		unsigned long long u;
	} val;
	s16 field_width;
	bool is_sign;

	while (*fmt) {
		/* skip any white space in format */
		/* white space in format matches any amount of
		 * white space, including none, in the input.
		 */
		if (isspace(*fmt)) {
			fmt = skip_spaces(++fmt);
			str = skip_spaces(str);
		}

		/* anything that is not a conversion must match exactly */
		if (*fmt != '%' && *fmt) {
			if (*fmt++ != *str++)
				break;
			continue;
		}

		if (!*fmt)
			break;
		++fmt;

		/* skip this conversion.
		 * advance both strings to next white space
		 */
		if (*fmt == '*') {
			if (!*str)
				break;
			while (!isspace(*fmt) && *fmt != '%' && *fmt) {
				/* '%*[' not yet supported, invalid format */
				if (*fmt == '[')
					return num;
				fmt++;
			}
			while (!isspace(*str) && *str)
				str++;
			continue;
		}

		/* get field width */
		field_width = -1;
		if (isdigit(*fmt)) {
			field_width = skip_atoi(&fmt);
			if (field_width <= 0)
				break;
		}

		/* get conversion qualifier */
		qualifier = -1;
		if (*fmt == 'h' || _tolower(*fmt) == 'l' ||
		    *fmt == 'z') {
			qualifier = *fmt++;
			if (unlikely(qualifier == *fmt)) {
				if (qualifier == 'h') {
					qualifier = 'H';
					fmt++;
				} else if (qualifier == 'l') {
					qualifier = 'L';
					fmt++;
				}
			}
		}

		if (!*fmt)
			break;

		if (*fmt == 'n') {
			/* return number of characters read so far */
			*va_arg(args, int *) = str - buf;
			++fmt;
			continue;
		}

		if (!*str)
			break;

		base = 10;
		is_sign = false;

		switch (*fmt++) {
		case 'c':
		{
			char *s = (char *)va_arg(args, char*);
			if (field_width == -1)
				field_width = 1;
			do {
				*s++ = *str++;
			} while (--field_width > 0 && *str);
			num++;
		}
		continue;
		case 's':
		{
			char *s = (char *)va_arg(args, char *);
			if (field_width == -1)
				field_width = SHRT_MAX;
			/* first, skip leading white space in buffer */
			str = skip_spaces(str);

			/* now copy until next white space */
			while (*str && !isspace(*str) && field_width--)
				*s++ = *str++;
			*s = '\0';
			num++;
		}
		continue;
		/*
		 * Warning: This implementation of the '[' conversion specifier
		 * deviates from its glibc counterpart in the following ways:
		 * (1) It does NOT support ranges i.e. '-' is NOT a special
		 *     character
		 * (2) It cannot match the closing bracket ']' itself
		 * (3) A field width is required
		 * (4) '%*[' (discard matching input) is currently not supported
		 *
		 * Example usage:
		 * ret = sscanf("00:0a:95","%2[^:]:%2[^:]:%2[^:]",
		 *		buf1, buf2, buf3);
		 * if (ret < 3)
		 *    // etc..
		 */
		case '[':
		{
			char *s = (char *)va_arg(args, char *);
			DECLARE_BITMAP(set, 256) = {0};
			unsigned int len = 0;
			bool negate = (*fmt == '^');

			/* field width is required */
			if (field_width == -1)
				return num;

			if (negate)
				++fmt;

			for ( ; *fmt && *fmt != ']'; ++fmt, ++len)
				__set_bit((u8)*fmt, set);

			/* no ']' or no character set found */
			if (!*fmt || !len)
				return num;
			++fmt;

			if (negate) {
				bitmap_complement(set, set, 256);
				/* exclude null '\0' byte */
				__clear_bit(0, set);
			}

			/* match must be non-empty */
			if (!test_bit((u8)*str, set))
				return num;

			while (test_bit((u8)*str, set) && field_width--)
				*s++ = *str++;
			*s = '\0';
			++num;
		}
		continue;
		case 'o':
			base = 8;
			break;
		case 'x':
		case 'X':
			base = 16;
			break;
		case 'i':
			base = 0;
			fallthrough;
		case 'd':
			is_sign = true;
			fallthrough;
		case 'u':
			break;
		case '%':
			/* looking for '%' in str */
			if (*str++ != '%')
				return num;
			continue;
		default:
			/* invalid format; stop here */
			return num;
		}

		/* have some sort of integer conversion.
		 * first, skip white space in buffer.
		 */
		str = skip_spaces(str);

		digit = *str;
		if (is_sign && digit == '-') {
			if (field_width == 1)
				break;

			digit = *(str + 1);
		}

		if (!digit
		    || (base == 16 && !isxdigit(digit))
		    || (base == 10 && !isdigit(digit))
		    || (base == 8 && !isodigit(digit))
		    || (base == 0 && !isdigit(digit)))
			break;

		if (is_sign)
			val.s = simple_strntoll(str, &next, base,
						field_width >= 0 ? field_width : INT_MAX);
		else
			val.u = simple_strntoull(str, &next, base,
						 field_width >= 0 ? field_width : INT_MAX);

		switch (qualifier) {
		case 'H':	/* that's 'hh' in format */
			if (is_sign)
				*va_arg(args, signed char *) = val.s;
			else
				*va_arg(args, unsigned char *) = val.u;
			break;
		case 'h':
			if (is_sign)
				*va_arg(args, short *) = val.s;
			else
				*va_arg(args, unsigned short *) = val.u;
			break;
		case 'l':
			if (is_sign)
				*va_arg(args, long *) = val.s;
			else
				*va_arg(args, unsigned long *) = val.u;
			break;
		case 'L':
			if (is_sign)
				*va_arg(args, long long *) = val.s;
			else
				*va_arg(args, unsigned long long *) = val.u;
			break;
		case 'z':
			*va_arg(args, size_t *) = val.u;
			break;
		default:
			if (is_sign)
				*va_arg(args, int *) = val.s;
			else
				*va_arg(args, unsigned int *) = val.u;
			break;
		}
		num++;

		if (!next)
			break;
		str = next;
	}

	return num;
}
EXPORT_SYMBOL(vsscanf);

/**
 * sscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	formatting of buffer
 * @...:	resulting arguments
 */
int sscanf(const char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsscanf(buf, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sscanf);
