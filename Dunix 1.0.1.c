

/*____________________________________________

Digital universe kernel   by Shishov Michael 



Ocotober  2019 

 _____________________________________________ */


#include <Dunix/kernel.h>


extern const char __initconst *const blacklist_hashes[];


/*TIMER FOR DUNIX   */


#include <asm/cpuinfo.h>

static void __iomem *timer_baseaddr;

static unsigned int freq_div_hz;
static unsigned int timer_clock_freq;

#define TCSR0	(0x00)
#define TLR0	(0x04)
#define TCR0	(0x08)
#define TCSR1	(0x10)
#define TLR1	(0x14)
#define TCR1	(0x18)

#define TCSR_MDT	(1<<0)
#define TCSR_UDT	(1<<1)
#define TCSR_GENT	(1<<2)
#define TCSR_CAPT	(1<<3)
#define TCSR_ARHT	(1<<4)
#define TCSR_LOAD	(1<<5)
#define TCSR_ENIT	(1<<6)
#define TCSR_ENT	(1<<7)
#define TCSR_TINT	(1<<8)
#define TCSR_PWMA	(1<<9)
#define TCSR_ENALL	(1<<10)

#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H


#include <stdarg.h>
#include <dunix/limits.h>
#include <dunix/linkage.h>
#include <dunix/stddef.h>
#include <dunix/types.h>
#include <dunix/compiler.h>
#include <dunix/bitops.h>
#include <dunix/log2.h>
#include <dunix/typecheck.h>
#include <dunix/printk.h>
#include <dunix/build_bug.h>
#include <asm/byteorder.h>
#include <asm/div64.h>
#include <asm/byteorder.h>
#include <asm/div64.h>
#include <uapi/dunix/kernel.h>
#include <asm/div64.h>
#include "USB_DRIVER_X64.c "
#include "DRIVERS_FOR_KEYBOARD_X_64.c "

#define STACK_MAGIC	0xdeadbeef

/**
 * REPEAT_BYTE - repeat the value @x multiple times as an unsigned long value
 * @x: value to repeat
 *
 * NOTE: @x is not checked for > 0xff; larger values produce odd results.
 */
#define REPEAT_BYTE(x)	((~0ul / 0xff) * (x))

/* @a is a power of 2 value */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)

/* generic data direction definitions */
#define READ			0
#define WRITE			1

/**
 * ARRAY_SIZE - get the number of elements in array @arr
 * @arr: array to be sized
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))

#define u64_to_user_ptr(x) (		\
{					\
	typecheck(u64, (x));		\
	(void __user *)(uintptr_t)(x);	\
}					\
)

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
/**
 * round_up - round up to next specified power of 2
 * @x: the value to round
 * @y: multiple to round up to (must be a power of 2)
 *
 * Rounds @x up to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding up, use roundup() below.
 */
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
/**
 * round_down - round down to next specified power of 2
 * @x: the value to round
 * @y: multiple to round down to (must be a power of 2)
 *
 * Rounds @x down to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding down, use rounddown() below.
 */
#define round_down(x, y) ((x) & ~__round_mask(x, y))

/**
 * FIELD_SIZEOF - get the size of a struct's field
 * @t: the target struct
 * @f: the target struct's field
 * Return: the size of @f in the struct definition without having a
 * declared instance of @t.
 */
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

#define typeof_member(T, m)	typeof(((T*)0)->m)

#define DIV_ROUND_UP __KERNEL_DIV_ROUND_UP

#define DIV_ROUND_DOWN_ULL(ll, d) \
	({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })

#define DIV_ROUND_UP_ULL(ll, d) \
	DIV_ROUND_DOWN_ULL((unsigned long long)(ll) + (d) - 1, (d))

#if BITS_PER_LONG == 32
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP_ULL(ll, d)
#else
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP(ll,d)
#endif

/**
 * roundup - round up to the next specified multiple
 * @x: the value to up
 * @y: multiple to round up to
 *
 * Rounds @x up to next multiple of @y. If @y will always be a power
 * of 2, consider using the faster round_up().
 *	
#define roundup(x, y) (					\
{							\
	typeof(y) __y = y;				\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
/**
 * rounddown - round down to next specified multiple
 * @x: the value to round
 * @y: multiple to round down to
 *
 * Rounds @x down to next multiple of @y. If @y will always be a power
 * of 2, consider using the faster round_down().
 */
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)

/*
 * Divide positive or negative dividend by positive or negative divisor
 * and round to closest integer. Result is undefined for negative
 * divisors if the dividend variable type is unsigned and for negative
 * dividends if the divisor variable type is unsigned.
 */
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(x) __x = x;				\
	typeof(divisor) __d = divisor;			\
	(((typeof(x))-1) > 0 ||				\
	 ((typeof(divisor))-1) > 0 ||			\
	 (((__x) > 0) == ((__d) > 0))) ?		\
		(((__x) + ((__d) / 2)) / (__d)) :	\
		(((__x) - ((__d) / 2)) / (__d));	\
}							\
)
/*
 * Same as above but for u64 dividends. divisor must be a 32-bit
 * number.
 */
#define DIV_ROUND_CLOSEST_ULL(x, divisor)(		\
{							\
	typeof(divisor) __d = divisor;			\
	unsigned long long _tmp = (x) + (__d) / 2;	\
	do_div(_tmp, __d);				\
	_tmp;						\
}							\
)

/*
 * Multiplies an integer by a fraction, while avoiding unnecessary
 * overflow or loss of precision.
 */
#define mult_frac(x, numer, denom)(			\
{							\
	typeof(x) quot = (x) / (denom);			\
	typeof(x) rem  = (x) % (denom);			\
	(quot * (numer)) + ((rem * (numer)) / (denom));	\
}							\
)


#define _RET_IP_		(unsigned long)__builtin_return_address(0)
#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })

#define sector_div(a, b) do_div(a, b)

/**
 * upper_32_bits - return bits 32-63 of a number
 * @n: the number we're accessing
 *
 * A basic shift-right of a 64- or 32-bit quantity.  Use this to suppress
 * the "right shift count >= width of type" warning when that quantity is
 * 32-bits.
 */
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((u32)(n))

struct completion;
struct pt_regs;
struct user;

#ifdef CONFIG_PREEMPT_VOLUNTARY
extern int _cond_resched(void);
# define might_resched() _cond_resched()
#else
# define might_resched() do { } while (0)
#endif

#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
extern void ___might_sleep(const char *file, int line, int preempt_offset);
extern void __might_sleep(const char *file, int line, int preempt_offset);
extern void __cant_sleep(const char *file, int line, int preempt_offset);

/**
 * might_sleep - annotation for functions that can sleep
 *
 * this macro will print a stack trace if it is executed in an atomic
 * context (spinlock, irq-handler, ...). Additional sections where blocking is
 * not allowed can be annotated with non_block_start() and non_block_end()
 * pairs.
 *
 * This is a useful debugging help to be able to catch problems early and not
 * be bitten later when the calling function happens to sleep when it is not
 * supposed to.
 */
# define might_sleep() \
	do { __might_sleep(__FILE__, __LINE__, 0); might_resched(); } while (0)
/**
 * cant_sleep - annotation for functions that cannot sleep
 *
 * this macro will print a stack trace if it is executed with preemption enabled
 */
# define cant_sleep() \
	do { __cant_sleep(__FILE__, __LINE__, 0); } while (0)
# define sched_annotate_sleep()	(current->task_state_change = 0)
/**
 * non_block_start - annotate the start of section where sleeping is prohibited
 *
 * This is on behalf of the oom reaper, specifically when it is calling the mmu
 * notifiers. The problem is that if the notifier were to block on, for example,
 * mutex_lock() and if the process which holds that mutex were to perform a
 * sleeping memory allocation, the oom reaper is now blocked on completion of
 * that memory allocation. Other blocking calls like wait_event() pose similar
 * issues.
 */
# define non_block_start() (current->non_block_count++)
/**
 * non_block_end - annotate the end of section where sleeping is prohibited
 *
 * Closes a section opened by non_block_start().
 */
# define non_block_end() WARN_ON(current->non_block_count-- == 0)
#else
  static inline void ___might_sleep(const char *file, int line,
				   int preempt_offset) { }
  static inline void __might_sleep(const char *file, int line,
				   int preempt_offset) { }
# define might_sleep() do { might_resched(); } while (0)
# define cant_sleep() do { } while (0)
# define sched_annotate_sleep() do { } while (0)
# define non_block_start() do { } while (0)
# define non_block_end() do { } while (0)
#endif

#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)

/**
 * abs - return absolute value of an argument
 * @x: the value.  If it is unsigned type, it is converted to signed type first.
 *     char is treated as if it was signed (regardless of whether it really is)
 *     but the macro's return type is preserved as char.
 *
 * Return: an absolute value of x.
 */
#define abs(x)	__abs_choose_expr(x, long long,				\
		__abs_choose_expr(x, long,				\
		__abs_choose_expr(x, int,				\
		__abs_choose_expr(x, short,				\
		__abs_choose_expr(x, char,				\
		__builtin_choose_expr(					\
			__builtin_types_compatible_p(typeof(x), char),	\
			(char)({ signed char __x = (x); __x<0?-__x:__x; }), \
			((void)0)))))))

#define __abs_choose_expr(x, type, other) __builtin_choose_expr(	\
	__builtin_types_compatible_p(typeof(x),   signed type) ||	\
	__builtin_types_compatible_p(typeof(x), unsigned type),		\
	({ signed type __x = (x); __x < 0 ? -__x : __x; }), other)

/**
 * reciprocal_scale - "scale" a value into range [0, ep_ro)
 * @val: value
 * @ep_ro: right open interval endpoint
 *
 * Perform a "reciprocal multiplication" in order to "scale" a value into
 * range [0, @ep_ro), where the upper interval endpoint is right-open.
 * This is useful, e.g. for accessing a index of an array containing
 * @ep_ro elements, for example. Think of it as sort of modulus, only that
 * the result isn't that of modulo. ;) Note that if initial input is a
 * small value, then result will return 0.
 *
 * Return: a result based on @val in interval [0, @ep_ro).
 */
static inline u32 reciprocal_scale(u32 val, u32 ep_ro)
{
	return (u32)(((u64) val * ep_ro) >> 32);
}

#if defined(CONFIG_MMU) && \
	(defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_DEBUG_ATOMIC_SLEEP))
#define might_fault() __might_fault(__FILE__, __LINE__)
void __might_fault(const char *file, int line);
#else
static inline void might_fault(void) { }
#endif

extern struct atomic_notifier_head panic_notifier_list;
extern long (*panic_blink)(int state);
__printf(1, 2)
void panic(const char *fmt, ...) __noreturn __cold;
void nmi_panic(struct pt_regs *regs, const char *msg);
extern void oops_enter(void);
extern void oops_exit(void);
void print_oops_end_marker(void);
extern int oops_may_print(void);
void do_exit(long error_code) __noreturn;
void complete_and_exit(struct completion *, long) __noreturn;

#ifdef CONFIG_ARCH_HAS_REFCOUNT
void refcount_error_report(struct pt_regs *regs, const char *err);
#else
static inline void refcount_error_report(struct pt_regs *regs, const char *err)
{ }
#endif

/* Internal, do not use. */
int __must_check _kstrtoul(const char *s, unsigned int base, unsigned long *res);
int __must_check _kstrtol(const char *s, unsigned int base, long *res);

int __must_check kstrtoull(const char *s, unsigned int base, unsigned long long *res);
int __must_check kstrtoll(const char *s, unsigned int base, long long *res);

/**
 * kstrtoul - convert a string to an unsigned long
 * @s: The start of the string. The string must be null-terminated, and may also
 *  include a single newline before its terminating null. The first character
 *  may also be a plus sign, but not a minus sign.
 * @base: The number base to use. The maximum supported base is 16. If base is
 *  given as 0, then the base of the string is automatically detected with the
 *  conventional semantics - If it begins with 0x the number will be parsed as a
 *  hexadecimal (case insensitive), if it otherwise begins with 0, it will be
 *  parsed as an octal number. Otherwise it will be parsed as a decimal.
 * @res: Where to write the result of the conversion on success.
 *
 * Returns 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
 * Used as a replacement for the obsolete simple_strtoull. Return code must
 * be checked.
*/
static inline int __must_check kstrtoul(const char *s, unsigned int base, unsigned long *res)
{
	/*
	 * We want to shortcut function call, but
	 * __builtin_types_compatible_p(unsigned long, unsigned long long) = 0.
	 */
	if (sizeof(unsigned long) == sizeof(unsigned long long) &&
	    __alignof__(unsigned long) == __alignof__(unsigned long long))
		return kstrtoull(s, base, (unsigned long long *)res);
	else
		return _kstrtoul(s, base, res);
}

/**
 * kstrtol - convert a string to a long
 * @s: The start of the string. The string must be null-terminated, and may also
 *  include a single newline before its terminating null. The first character
 *  may also be a plus sign or a minus sign.
 * @base: The number base to use. The maximum supported base is 16. If base is
 *  given as 0, then the base of the string is automatically detected with the
 *  conventional semantics - If it begins with 0x the number will be parsed as a
 *  hexadecimal (case insensitive), if it otherwise begins with 0, it will be
 *  parsed as an octal number. Otherwise it will be parsed as a decimal.
 * @res: Where to write the result of the conversion on success.
 *
 * Returns 0 on success, -ERANGE on overflow and -EINVAL on parsing error.
 * Used as a replacement for the obsolete simple_strtoull. Return code must
 * be checked.
 */
static inline int __must_check kstrtol(const char *s, unsigned int base, long *res)
{
	/*
	 * We want to shortcut function call, but
	 * __builtin_types_compatible_p(long, long long) = 0.
	 */
	if (sizeof(long) == sizeof(long long) &&
	    __alignof__(long) == __alignof__(long long))
		return kstrtoll(s, base, (long long *)res);
	else
		return _kstrtol(s, base, res);
}

int __must_check kstrtouint(const char *s, unsigned int base, unsigned int *res);
int __must_check kstrtoint(const char *s, unsigned int base, int *res);

static inline int __must_check kstrtou64(const char *s, unsigned int base, u64 *res)
{
	return kstrtoull(s, base, res);
}

static inline int __must_check kstrtos64(const char *s, unsigned int base, s64 *res)
{
	return kstrtoll(s, base, res);
}

static inline int __must_check kstrtou32(const char *s, unsigned int base, u32 *res)
{
	return kstrtouint(s, base, res);
}

static inline int __must_check kstrtos32(const char *s, unsigned int base, s32 *res)
{
	return kstrtoint(s, base, res);
}

int __must_check kstrtou16(const char *s, unsigned int base, u16 *res);
int __must_check kstrtos16(const char *s, unsigned int base, s16 *res);
int __must_check kstrtou8(const char *s, unsigned int base, u8 *res);
int __must_check kstrtos8(const char *s, unsigned int base, s8 *res);
int __must_check kstrtobool(const char *s, bool *res);

int __must_check kstrtoull_from_user(const char __user *s, size_t count, unsigned int base, unsigned long long *res);
int __must_check kstrtoll_from_user(const char __user *s, size_t count, unsigned int base, long long *res);
int __must_check kstrtoul_from_user(const char __user *s, size_t count, unsigned int base, unsigned long *res);
int __must_check kstrtol_from_user(const char __user *s, size_t count, unsigned int base, long *res);
int __must_check kstrtouint_from_user(const char __user *s, size_t count, unsigned int base, unsigned int *res);
int __must_check kstrtoint_from_user(const char __user *s, size_t count, unsigned int base, int *res);
int __must_check kstrtou16_from_user(const char __user *s, size_t count, unsigned int base, u16 *res);
int __must_check kstrtos16_from_user(const char __user *s, size_t count, unsigned int base, s16 *res);
int __must_check kstrtou8_from_user(const char __user *s, size_t count, unsigned int base, u8 *res);
int __must_check kstrtos8_from_user(const char __user *s, size_t count, unsigned int base, s8 *res);
int __must_check kstrtobool_from_user(const char __user *s, size_t count, bool *res);

static inline int __must_check kstrtou64_from_user(const char __user *s, size_t count, unsigned int base, u64 *res)
{
	return kstrtoull_from_user(s, count, base, res);
}

static inline int __must_check kstrtos64_from_user(const char __user *s, size_t count, unsigned int base, s64 *res)
{
	return kstrtoll_from_user(s, count, base, res);
}

static inline int __must_check kstrtou32_from_user(const char __user *s, size_t count, unsigned int base, u32 *res)
{
	return kstrtouint_from_user(s, count, base, res);
}

static inline int __must_check kstrtos32_from_user(const char __user *s, size_t count, unsigned int base, s32 *res)
{
	return kstrtoint_from_user(s, count, base, res);
}

/* Obsolete, do not use.  Use kstrto<foo> instead */

extern unsigned long simple_strtoul(const char *,char **,unsigned int);
extern long simple_strtol(const char *,char **,unsigned int);
extern unsigned long long simple_strtoull(const char *,char **,unsigned int);
extern long long simple_strtoll(const char *,char **,unsigned int);

extern int num_to_str(char *buf, int size,
		      unsigned long long num, unsigned int width);

/* lib/printf utilities */

extern __printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
extern __printf(2, 0) int vsprintf(char *buf, const char *, va_list);
extern __printf(3, 4)
int snprintf(char *buf, size_t size, const char *fmt, ...);
extern __printf(3, 0)
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
extern __printf(3, 4)
int scnprintf(char *buf, size_t size, const char *fmt, ...);
extern __printf(3, 0)
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
extern __printf(2, 3) __malloc
char *kasprintf(gfp_t gfp, const char *fmt, ...);
extern __printf(2, 0) __malloc
char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
extern __printf(2, 0)
const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);

extern __scanf(2, 3)
int sscanf(const char *, const char *, ...);
extern __scanf(2, 0)
int vsscanf(const char *, const char *, va_list);

extern int get_option(char **str, int *pint);
extern char *get_options(const char *str, int nints, int *ints);
extern unsigned long long memparse(const char *ptr, char **retptr);
extern bool parse_option_str(const char *str, const char *option);
extern char *next_arg(char *args, char **param, char **val);

extern int core_kernel_text(unsigned long addr);
extern int init_kernel_text(unsigned long addr);
extern int core_kernel_data(unsigned long addr);
extern int __kernel_text_address(unsigned long addr);
extern int kernel_text_address(unsigned long addr);
extern int func_ptr_is_kernel_text(void *ptr);

u64 int_pow(u64 base, unsigned int exp);
unsigned long int_sqrt(unsigned long);

#if BITS_PER_LONG < 64
u32 int_sqrt64(u64 x);
#else
static inline u32 int_sqrt64(u64 x)
{
	return (u32)int_sqrt(x);
}
#endif

extern void bust_spinlocks(int yes);
extern int oops_in_progress;		/* If set, an oops, panic(), BUG() or die() is in progress */
extern int panic_timeout;
extern unsigned long panic_print;
extern int panic_on_oops;
extern int panic_on_unrecovered_nmi;
extern int panic_on_io_nmi;
extern int panic_on_warn;
extern int sysctl_panic_on_rcu_stall;
extern int sysctl_panic_on_stackoverflow;

extern bool crash_kexec_post_notifiers;

/*
 * panic_cpu is used for synchronizing panic() and crash_kexec() execution. It
 * holds a CPU number which is executing panic() currently. A value of
 * PANIC_CPU_INVALID means no CPU has entered panic() or crash_kexec().
 */
extern atomic_t panic_cpu;
#define PANIC_CPU_INVALID	-1

/*
 * Only to be used by arch init code. If the user over-wrote the default
 * CONFIG_PANIC_TIMEOUT, honor it.
 */
static inline void set_arch_panic_timeout(int timeout, int arch_default_timeout)
{
	if (panic_timeout == arch_default_timeout)
		panic_timeout = timeout;
}
extern const char *print_tainted(void);
enum lockdep_ok {
	LOCKDEP_STILL_OK,
	LOCKDEP_NOW_UNRELIABLE
};
extern void add_taint(unsigned flag, enum lockdep_ok);
extern int test_taint(unsigned flag);
extern unsigned long get_taint(void);
extern int root_mountflags;

extern bool early_boot_irqs_disabled;

/*
 * Values used for system_state. Ordering of the states must not be changed
 * as code checks for <, <=, >, >= STATE.
 */
extern enum system_states {
	SYSTEM_BOOTING,
	SYSTEM_SCHEDULING,
	SYSTEM_RUNNING,
	SYSTEM_HALT,
	SYSTEM_POWER_OFF,
	SYSTEM_RESTART,
	SYSTEM_SUSPEND,
} system_state;

/* This cannot be an enum because some may be used in assembly source. */
#define TAINT_PROPRIETARY_MODULE	0
#define TAINT_FORCED_MODULE		1
#define TAINT_CPU_OUT_OF_SPEC		2
#define TAINT_FORCED_RMMOD		3
#define TAINT_MACHINE_CHECK		4
#define TAINT_BAD_PAGE			5
#define TAINT_USER			6
#define TAINT_DIE			7
#define TAINT_OVERRIDDEN_ACPI_TABLE	8
#define TAINT_WARN			9
#define TAINT_CRAP			10
#define TAINT_FIRMWARE_WORKAROUND	11
#define TAINT_OOT_MODULE		12
#define TAINT_UNSIGNED_MODULE		13
#define TAINT_SOFTLOCKUP		14
#define TAINT_LIVEPATCH			15
#define TAINT_AUX			16
#define TAINT_RANDSTRUCT		17
#define TAINT_FLAGS_COUNT		18

struct taint_flag {
	char c_true;	/* character printed when tainted */
	char c_false;	/* character printed when not tainted */
	bool module;	/* also show as a per-module taint flag */
};

extern const struct taint_flag taint_flags[TAINT_FLAGS_COUNT];

extern const char hex_asc[];
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]

static inline char *hex_byte_pack(char *buf, u8 byte)
{
	*buf++ = hex_asc_hi(byte);
	*buf++ = hex_asc_lo(byte);
	return buf;
}

extern const char hex_asc_upper[];
#define hex_asc_upper_lo(x)	hex_asc_upper[((x) & 0x0f)]
#define hex_asc_upper_hi(x)	hex_asc_upper[((x) & 0xf0) >> 4]

static inline char *hex_byte_pack_upper(char *buf, u8 byte)
{
	*buf++ = hex_asc_upper_hi(byte);
	*buf++ = hex_asc_upper_lo(byte);
	return buf;
}

extern int hex_to_bin(char ch);
extern int __must_check hex2bin(u8 *dst, const char *src, size_t count);
extern char *bin2hex(char *dst, const void *src, size_t count);

bool mac_pton(const char *s, u8 *mac);

/*
 * General tracing related utility functions - trace_printk(),
 * tracing_on/tracing_off and tracing_start()/tracing_stop
 *
 * Use tracing_on/tracing_off when you want to quickly turn on or off
 * tracing. It simply enables or disables the recording of the trace events.
 * This also corresponds to the user space /sys/kernel/debug/tracing/tracing_on
 * file, which gives a means for the kernel and userspace to interact.
 * Place a tracing_off() in the kernel where you want tracing to end.
 * From user space, examine the trace, and then echo 1 > tracing_on
 * to continue tracing.
 *
 * tracing_stop/tracing_start has slightly more overhead. It is used
 * by things like suspend to ram where disabling the recording of the
 * trace is not enough, but tracing must actually stop because things
 * like calling smp_processor_id() may crash the system.
 *
 * Most likely, you want to use tracing_on/tracing_off.
 */

enum ftrace_dump_mode {
	DUMP_NONE,
	DUMP_ALL,
	DUMP_ORIG,
};

#ifdef CONFIG_TRACING
void tracing_on(void);
void tracing_off(void);
int tracing_is_on(void);
void tracing_snapshot(void);
void tracing_snapshot_alloc(void);

extern void tracing_start(void);
extern void tracing_stop(void);

static inline __printf(1, 2)
void ____trace_printk_check_format(const char *fmt, ...)
{
}
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)

/**
 * trace_printk - printf formatting in the ftrace buffer
 * @fmt: the printf format for printing
 *
 * Note: __trace_printk is an internal function for trace_printk() and
 *       the @ip is passed in via the trace_printk() macro.
 *
 * This function allows a kernel developer to debug fast path sections
 * that printk is not appropriate for. By scattering in various
 * printk like tracing in the code, a developer can quickly see
 * where problems are occurring.
 *
 * This is intended as a debugging tool for the developer only.
 * Please refrain from leaving trace_printks scattered around in
 * your code. (Extra memory is used for special buffers that are
 * allocated when trace_printk() is used.)
 *
 * A little optimization trick is done here. If there's only one
 * argument, there's no need to scan the string for printf formats.
 * The trace_puts() will suffice. But how can we take advantage of
 * using trace_puts() when trace_printk() has only one argument?
 * By stringifying the args and checking the size we can tell
 * whether or not there are args. __stringify((__VA_ARGS__)) will
 * turn into "()\0" with a size of 3 when there are no args, anything
 * else will be bigger. All we need to do is define a string to this,
 * and then take its size and compare to 3. If it's bigger, use
 * do_trace_printk() otherwise, optimize it to trace_puts(). Then just
 * let gcc optimize the rest.
 */

#define trace_printk(fmt, ...)				\
do {							\
	char _______STR[] = __stringify((__VA_ARGS__));	\
	if (sizeof(_______STR) > 3)			\
		do_trace_printk(fmt, ##__VA_ARGS__);	\
	else						\
		trace_puts(fmt);			\
} while (0)

#define do_trace_printk(fmt, args...)					\
do {									\
	static const char *trace_printk_fmt __used			\
		__attribute__((section("__trace_printk_fmt"))) =	\
		__builtin_constant_p(fmt) ? fmt : NULL;			\
									\
	__trace_printk_check_format(fmt, ##args);			\
									\
	if (__builtin_constant_p(fmt))					\
		__trace_bprintk(_THIS_IP_, trace_printk_fmt, ##args);	\
	else								\
		__trace_printk(_THIS_IP_, fmt, ##args);			\
} while (0)

extern __printf(2, 3)
int __trace_bprintk(unsigned long ip, const char *fmt, ...);

extern __printf(2, 3)
int __trace_printk(unsigned long ip, const char *fmt, ...);

/**
 * trace_puts - write a string into the ftrace buffer
 * @str: the string to record
 *
 * Note: __trace_bputs is an internal function for trace_puts and
 *       the @ip is passed in via the trace_puts macro.
 *
 * This is similar to trace_printk() but is made for those really fast
 * paths that a developer wants the least amount of "Heisenbug" effects,
 * where the processing of the print format is still too much.
 *
 * This function allows a kernel developer to debug fast path sections
 * that printk is not appropriate for. By scattering in various
 * printk like tracing in the code, a developer can quickly see
 * where problems are occurring.
 *
 * This is intended as a debugging tool for the developer only.
 * Please refrain from leaving trace_puts scattered around in
 * your code. (Extra memory is used for special buffers that are
 * allocated when trace_puts() is used.)
 *
 * Returns: 0 if nothing was written, positive # if string was.
 *  (1 when __trace_bputs is used, strlen(str) when __trace_puts is used)
 */

#define trace_puts(str) ({						\
	static const char *trace_printk_fmt __used			\
		__attribute__((section("__trace_printk_fmt"))) =	\
		__builtin_constant_p(str) ? str : NULL;			\
									\
	if (__builtin_constant_p(str))					\
		__trace_bputs(_THIS_IP_, trace_printk_fmt);		\
	else								\
		__trace_puts(_THIS_IP_, str, strlen(str));		\
})
extern int __trace_bputs(unsigned long ip, const char *str);
extern int __trace_puts(unsigned long ip, const char *str, int size);

extern void trace_dump_stack(int skip);

/*
 * The double __builtin_constant_p is because gcc will give us an error
 * if we try to allocate the static variable to fmt if it is not a
 * constant. Even with the outer if statement.
 */
#define ftrace_vprintk(fmt, vargs)					\
do {									\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt __used		\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__ftrace_vbprintk(_THIS_IP_, trace_printk_fmt, vargs);	\
	} else								\
		__ftrace_vprintk(_THIS_IP_, fmt, vargs);		\
} while (0)

extern __printf(2, 0) int
__ftrace_vbprintk(unsigned long ip, const char *fmt, va_list ap);

extern __printf(2, 0) int
__ftrace_vprintk(unsigned long ip, const char *fmt, va_list ap);

extern void ftrace_dump(enum ftrace_dump_mode oops_dump_mode);
#else
static inline void tracing_start(void) { }
static inline void tracing_stop(void) { }
static inline void trace_dump_stack(int skip) { }

static inline void tracing_on(void) { }
static inline void tracing_off(void) { }
static inline int tracing_is_on(void) { return 0; }
static inline void tracing_snapshot(void) { }
static inline void tracing_snapshot_alloc(void) { }

static inline __printf(1, 2)
int trace_printk(const char *fmt, ...)
{
	return 0;
}
static __printf(1, 0) inline int
ftrace_vprintk(const char *fmt, va_list ap)
{
	return 0;
}
static inline void ftrace_dump(enum ftrace_dump_mode oops_dump_mode) { }
#endif /* CONFIG_TRACING */

/*
 * min()/max()/clamp() macros must accomplish three things:
 *
 * - avoid multiple evaluations of the arguments (so side-effects like
 *   "x++" happen only once) when non-constant.
 * - perform strict type-checking (to generate warnings instead of
 *   nasty runtime surprises). See the "unnecessary" pointer comparison
 *   in __typecheck().
 * - retain result as a constant expressions when called with only
 *   constant expressions (to avoid tripping VLA warnings in stack
 *   allocation usage).
 */
#define __typecheck(x, y) \
		(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))

/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

#define __no_side_effects(x, y) \
		(__is_constexpr(x) && __is_constexpr(y))

#define __safe_cmp(x, y) \
		(__typecheck(x, y) && __no_side_effects(x, y))

#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))

#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })

#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))

/**
 * min - return minimum of two values of the same or compatible types
 * @x: first value
 * @y: second value
 */
#define min(x, y)	__careful_cmp(x, y, <)

/**
 * max - return maximum of two values of the same or compatible types
 * @x: first value
 * @y: second value
 */
#define max(x, y)	__careful_cmp(x, y, >)

/**
 * min3 - return minimum of three values
 * @x: first value
 * @y: second value
 * @z: third value
 */
#define min3(x, y, z) min((typeof(x))min(x, y), z)

/**
 * max3 - return maximum of three values
 * @x: first value
 * @y: second value
 * @z: third value
 */
#define max3(x, y, z) max((typeof(x))max(x, y), z)

/**
 * min_not_zero - return the minimum that is _not_ zero, unless both are zero
 * @x: value1
 * @y: value2
 */
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })

/**
 * clamp - return a value clamped to a given range with strict typechecking
 * @val: current value
 * @lo: lowest allowable value
 * @hi: highest allowable value
 *
 * This macro does strict typechecking of @lo/@hi to make sure they are of the
 * same type as @val.  See the unnecessary pointer comparisons.
 */
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)

/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max/clamp at all, of course.
 */

/**
 * min_t - return minimum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define min_t(type, x, y)	__careful_cmp((type)(x), (type)(y), <)

/**
 * max_t - return maximum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define max_t(type, x, y)	__careful_cmp((type)(x), (type)(y), >)

/**
 * clamp_t - return a value clamped to a given range using a given type
 * @type: the type of variable to use
 * @val: current value
 * @lo: minimum allowable value
 * @hi: maximum allowable value
 *
 * This macro does no typechecking and uses temporary variables of type
 * @type to make all the comparisons.
 */
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)

/**
 * clamp_val - return a value clamped to a given range using val's type
 * @val: current value
 * @lo: minimum allowable value
 * @hi: maximum allowable value
 *
 * This macro does no typechecking and uses temporary variables of whatever
 * type the input argument @val is.  This is useful when @val is an unsigned
 * type and @lo and @hi are literals that will otherwise be assigned a signed
 * integer type.
 */
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)


/**
 * swap - swap values of @a and @b
 * @a: first value
 * @b: second value
 */
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

/* This counts to 12. Any more, it will return 13th argument. */
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _n, X...) _n
#define COUNT_ARGS(X...) __COUNT_ARGS(, ##X, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define __CONCAT(a, b) a ## b
#define CONCATENATE(a, b) __CONCAT(a, b)

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

/**
 * container_of_safe - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 * If IS_ERR_OR_NULL(ptr), ptr is returned unchanged.
 */
#define container_of_safe(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	IS_ERR_OR_NULL(__mptr) ? ERR_CAST(__mptr) :			\
		((type *)(__mptr - offsetof(type, member))); })

/* Rebuild everything on CONFIG_FTRACE_MCOUNT_RECORD */
#ifdef CONFIG_FTRACE_MCOUNT_RECORD
# define REBUILD_DUE_TO_FTRACE_MCOUNT_RECORD
#endif

/* Permissions on a sysfs file: you didn't miss the 0 prefix did you? */
#define VERIFY_OCTAL_PERMISSIONS(perms)						\
	(BUILD_BUG_ON_ZERO((perms) < 0) +					\
	 BUILD_BUG_ON_ZERO((perms) > 0777) +					\
	 /* USER_READABLE >= GROUP_READABLE >= OTHER_READABLE */		\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 4) < (((perms) >> 3) & 4)) +	\
	 BUILD_BUG_ON_ZERO((((perms) >> 3) & 4) < ((perms) & 4)) +		\
	 /* USER_WRITABLE >= GROUP_WRITABLE */					\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 2) < (((perms) >> 3) & 2)) +	\
	 /* OTHER_WRITABLE?  Generally considered a bad idea. */		\
	 BUILD_BUG_ON_ZERO((perms) & 2) +					\
	 (perms))
#endif

static unsigned int (*read_fn)(void __iomem *);
static void (*write_fn)(u32, void __iomem *);

static void timer_write32(u32 val, void __iomem *addr)
{
	iowrite32(val, addr);
}

static unsigned int timer_read32(void __iomem *addr)
{
	return ioread32(addr);
}

static void timer_write32_be(u32 val, void __iomem *addr)
{
	iowrite32be(val, addr);
}

static unsigned int timer_read32_be(void __iomem *addr)
{
	return ioread32be(addr);
}

static inline void xdunix_timer0_stop(void)
{
	write_fn(read_fn(timer_baseaddr + TCSR0) & ~TCSR_ENT,
		 timer_baseaddr + TCSR0);
}

static inline void xdunix_timer0_start_periodic(unsigned long load_val)
{
	if (!load_val)
		load_val = 1;
	/* loading value to timer reg */
	write_fn(load_val, timer_baseaddr + TLR0);

	/* load the initial value */
	write_fn(TCSR_LOAD, timer_baseaddr + TCSR0);

	/* see timer data sheet for detail
	 * !ENALL - don't enable 'em all
	 * !PWMA - disable pwm
	 * TINT - clear interrupt status
	 * ENT- enable timer itself
	 * ENIT - enable interrupt
	 * !LOAD - clear the bit to let go
	 * ARHT - auto reload
	 * !CAPT - no external trigger
	 * !GENT - no external signal
	 * UDT - set the timer as down counter
	 * !MDT0 - generate mode
	 */
	write_fn(TCSR_TINT|TCSR_ENIT|TCSR_ENT|TCSR_ARHT|TCSR_UDT,
		 timer_baseaddr + TCSR0);
}

static inline void xdunix_timer0_start_oneshot(unsigned long load_val)
{
	if (!load_val)
		load_val = 1;
	/* loading value to timer reg */
	write_fn(load_val, timer_baseaddr + TLR0);

	/* load the initial value */
	write_fn(TCSR_LOAD, timer_baseaddr + TCSR0);

	write_fn(TCSR_TINT|TCSR_ENIT|TCSR_ENT|TCSR_ARHT|TCSR_UDT,
		 timer_baseaddr + TCSR0);
}

static int xdunix_timer_set_next_event(unsigned long delta,
					struct clock_event_device *dev)
{
	pr_debug("%s: next event, delta %x\n", __func__, (u32)delta);
	xilinx_timer0_start_oneshot(delta);
	return 0;
}

static int xdunix_timer_shutdown(struct clock_event_device *evt)
{
	pr_info("%s\n", __func__);
	xilinx_timer0_stop();
	return 0;
}

static int xdunix_timer_set_periodic(struct clock_event_device *evt)
{
	pr_info("%s\n", __func__);
	xilinx_timer0_start_periodic(freq_div_hz);
	return 0;
}

static struct clock_event_device clockevent_xilinx_timer = {
	.name			= "xilinx_clockevent",
	.features		= CLOCK_EVT_FEAT_ONESHOT |
				  CLOCK_EVT_FEAT_PERIODIC,
	.shift			= 8,
	.rating			= 300,
	.set_next_event		= xilinx_timer_set_next_event,
	.set_state_shutdown	= xilinx_timer_shutdown,
	.set_state_periodic	= xilinx_timer_set_periodic,
};

static inline void timer_ack(void)
{
	write_fn(read_fn(timer_baseaddr + TCSR0), timer_baseaddr + TCSR0);
}

static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *evt = &clockevent_xilinx_timer;
	timer_ack();
	evt->event_handler(evt);
	return IRQ_HANDLED;
}

static struct irqaction timer_irqaction = {
	.handler = timer_interrupt,
	.flags = IRQF_TIMER,
	.name = "timer",
	.dev_id = &clockevent_xilinx_timer,
};

static __init int xilinx_clockevent_init(void)
{
	clockevent_xilinx_timer.mult =
		div_sc(timer_clock_freq, NSEC_PER_SEC,
				clockevent_xilinx_timer.shift);
	clockevent_xilinx_timer.max_delta_ns =
		clockevent_delta2ns((u32)~0, &clockevent_xilinx_timer);
	clockevent_xilinx_timer.max_delta_ticks = (u32)~0;
	clockevent_xilinx_timer.min_delta_ns =
		clockevent_delta2ns(1, &clockevent_xilinx_timer);
	clockevent_xilinx_timer.min_delta_ticks = 1;
	clockevent_xilinx_timer.cpumask = cpumask_of(0);
	clockevents_register_device(&clockevent_xilinx_timer);

	return 0;
}

static u64 xilinx_clock_read(void)
{
	return read_fn(timer_baseaddr + TCR1);
}

static u64 xilinx_read(struct clocksource *cs)
{
	/* reading actual value of timer 1 */
	return (u64)xilinx_clock_read();
}

static struct timecounter xilinx_tc = {
	.cc = NULL,
};

static u64 xilinx_cc_read(const struct cyclecounter *cc)
{
	return xilinx_read(NULL);
}

static struct cyclecounter xilinx_cc = {
	.read = xilinx_cc_read,
	.mask = CLOCKSOURCE_MASK(32),
	.shift = 8,
};

static int __init init_xilinx_timecounter(void)
{
	xilinx_cc.mult = div_sc(timer_clock_freq, NSEC_PER_SEC,
				xilinx_cc.shift);

	timecounter_init(&xilinx_tc, &xilinx_cc, sched_clock());

	return 0;
}

static struct clocksource clocksource_microblaze = {
	.name		= "xilinx_clocksource",
	.rating		= 300,
	.read		= xilinx_read,
	.mask		= CLOCKSOURCE_MASK(32),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

static int __init xilinx_clocksource_init(void)
{
	int ret;

	ret = clocksource_register_hz(&clocksource_microblaze,
				      timer_clock_freq);
	if (ret) {
		pr_err("failed to register clocksource");
		return ret;
	}

	/* stop timer1 */
	write_fn(read_fn(timer_baseaddr + TCSR1) & ~TCSR_ENT,
		 timer_baseaddr + TCSR1);
	/* start timer1 - up counting without interrupt */
	write_fn(TCSR_TINT|TCSR_ENT|TCSR_ARHT, timer_baseaddr + TCSR1);

	/* register timecounter - for ftrace support */
	return init_xilinx_timecounter();
}

static int __init xilinx_timer_init(struct device_node *timer)
{
	struct clk *clk;
	static int initialized;
	u32 irq;
	u32 timer_num = 1;
	int ret;

	if (initialized)
		return -EINVAL;

	initialized = 1;

	timer_baseaddr = of_iomap(timer, 0);
	if (!timer_baseaddr) {
		pr_err("ERROR: invalid timer base address\n");
		return -ENXIO;
	}

	write_fn = timer_write32;
	read_fn = timer_read32;

	write_fn(TCSR_MDT, timer_baseaddr + TCSR0);
	if (!(read_fn(timer_baseaddr + TCSR0) & TCSR_MDT)) {
		write_fn = timer_write32_be;
		read_fn = timer_read32_be;
	}

	irq = irq_of_parse_and_map(timer, 0);
	if (irq <= 0) {
		pr_err("Failed to parse and map irq");
		return -EINVAL;
	}

	of_property_read_u32(timer, "xlnx,one-timer-only", &timer_num);
	if (timer_num) {
		pr_err("Please enable two timers in HW\n");
		return -EINVAL;
	}

	pr_info("%pOF: irq=%d\n", timer, irq);

	clk = of_clk_get(timer, 0);
	if (IS_ERR(clk)) {
		pr_err("ERROR: timer CCF input clock not found\n");
		/* If there is clock-frequency property than use it */
		of_property_read_u32(timer, "clock-frequency",
				    &timer_clock_freq);
	} else {
		timer_clock_freq = clk_get_rate(clk);
	}

	if (!timer_clock_freq) {
		pr_err("ERROR: Using CPU clock frequency\n");
		timer_clock_freq = cpuinfo.cpu_clock_freq;
	}

	freq_div_hz = timer_clock_freq / HZ;

	ret = setup_irq(irq, &timer_irqaction);
	if (ret) {
		pr_err("Failed to setup IRQ");
		return ret;
	}

	ret = xilinx_clocksource_init();
	if (ret)
		return ret;

	ret = xilinx_clockevent_init();
	if (ret)
		return ret;

	sched_clock_register(xilinx_clock_read, 32, timer_clock_freq);

	return 0;
}

TIMER_OF_DECLARE(xilinx_timer, "xlnx,xps-timer-1.00.a",
		       xilinx_timer_init);


/*
 * Copyright (C) 2007-2009 Michal Simek <monstr@monstr.eu>
 * Copyright (C) 2007-2009 PetaLogix
 * Copyright (C) 2006 Atmark Techno, Inc.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#ifndef _ASM_MICROBLAZE_SETUP_H
#define _ASM_MICROBLAZE_SETUP_H

#include <uapi/asm/setup.h>

# ifndef __ASSEMBLY__
extern unsigned int boot_cpuid; /* move to smp.h */

extern char cmd_line[COMMAND_LINE_SIZE];

extern char *klimit;

#   ifdef CONFIG_MMU
extern void mmu_reset(void);
#   endif /* CONFIG_MMU */

void time_init(void);
void init_IRQ(void);
void machine_early_init(const char *cmdline, unsigned int ram,
		unsigned int fdt, unsigned int msr, unsigned int tlb0,
		unsigned int tlb1);

void machine_restart(char *cmd);
void machine_shutdown(void);
void machine_halt(void);
void machine_power_off(void);

extern void *zalloc_maybe_bootmem(size_t size, gfp_t mask);

# endif /* __ASSEMBLY__ */
#endif /* _ASM_MICROBLAZE_SETUP_H */


#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <math.h>
#include <assert.h>
#include "Garbage_collector_for_Dunix.c"
#include "boot.asm"
#define LEN 100 
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#define KSYM_NAME_LEN		128


int time () 
{
	long int ttime;

	ttime=time(NULL); // We  need understand  curently  time 

	printf("Time : %s\n",ctime (&ttime) );

	return 0 ; 
}


// Launcher of the Dunix 

int start () {

     __assembly__ {
       
         section.text
      use16
      org 0x7C00
start:
mov ax, cs
mov ds, ax
mov si,a
cld
mov ah, 0x0e
mov bh,0
jmp puts_loop
puts_loop:
  lodsb
    test al , al
    jz text_
    int 10h
    jmp puts_loop
text_
mov ah,0
int 16h
cmp ah,0Eh
jz text_back
mov ah,0x0e
mov bh,0
int 10h
jmp text_
text_back:
mov ah,0x0e
mov bh,0
mov al,8
int 10h
section .data
a db 'Starting Dunix 1.0 ',0

    }

/* CPU control.
 * (C) 2001, 2002, 2003, 2004 Rusty Russell
 *
 * This code is licenced under the GPL.
 */
#include <dunix/proc_fs.h>
#include <dunix/smp.h>
#include <dunix/init.h>
#include <dunix/notifier.h>
#include <dunix/sched/signal.h>
#include <dunix/sched/hotplug.h>
#include <dunix/sched/isolation.h>
#include <dunix/sched/task.h>
#include <dunix/sched/smt.h>
#include <dunix/unistd.h>
#include <dunix/cpu.h>
#include <dunix/oom.h>
#include <dunix/rcupdate.h>
#include <dunix/export.h>
#include <dunix/bug.h>
#include <dunix/kthread.h>
#include <dunix/stop_machine.h>
#include <dunix/mutex.h>
#include <dunix/gfp.h>
#include <dunix/suspend.h>
#include <dunix/lockdep.h>
#include <dunix/tick.h>
#include <dunix/irq.h>
#include <dunix/nmi.h>
#include <dunix/smpboot.h>
#include <dunix/relay.h>
#include <dunix/slab.h>
#include <dunix/percpu-rwsem.h>

#include <trace/events/power.h>
#define CREATE_TRACE_POINTS
#include <trace/events/cpuhp.h>

#include "smpboot.h"

/**
 * cpuhp_cpu_state - Per cpu hotplug state storage
 * @state:	The current cpu state
 * @target:	The target state
 * @thread:	Pointer to the hotplug thread
 * @should_run:	Thread should execute
 * @rollback:	Perform a rollback
 * @single:	Single callback invocation
 * @bringup:	Single callback bringup or teardown selector
 * @cb_state:	The state for a single callback (install/uninstall)
 * @result:	Result of the operation
 * @done_up:	Signal completion to the issuer of the task for cpu-up
 * @done_down:	Signal completion to the issuer of the task for cpu-down
 */
struct cpuhp_cpu_state {
	enum cpuhp_state	state;
	enum cpuhp_state	target;
	enum cpuhp_state	fail;
#ifdef CONFIG_SMP
	struct task_struct	*thread;
	bool			should_run;
	bool			rollback;
	bool			single;
	bool			bringup;
	struct hlist_node	*node;
	struct hlist_node	*last;
	enum cpuhp_state	cb_state;
	int			result;
	struct completion	done_up;
	struct completion	done_down;
#endif
};

static DEFINE_PER_CPU(struct cpuhp_cpu_state, cpuhp_state) = {
	.fail = CPUHP_INVALID,
};

#ifdef CONFIG_SMP
cpumask_t cpus_booted_once_mask;
#endif

#if defined(CONFIG_LOCKDEP) && defined(CONFIG_SMP)
static struct lockdep_map cpuhp_state_up_map =
	STATIC_LOCKDEP_MAP_INIT("cpuhp_state-up", &cpuhp_state_up_map);
static struct lockdep_map cpuhp_state_down_map =
	STATIC_LOCKDEP_MAP_INIT("cpuhp_state-down", &cpuhp_state_down_map);


static inline void cpuhp_lock_acquire(bool bringup)
{
	lock_map_acquire(bringup ? &cpuhp_state_up_map : &cpuhp_state_down_map);
}

static inline void cpuhp_lock_release(bool bringup)
{
	lock_map_release(bringup ? &cpuhp_state_up_map : &cpuhp_state_down_map);
}
#else

static inline void cpuhp_lock_acquire(bool bringup) { }
static inline void cpuhp_lock_release(bool bringup) { }

#endif

/**
 * cpuhp_step - Hotplug state machine step
 * @name:	Name of the step
 * @startup:	Startup function of the step
 * @teardown:	Teardown function of the step
 * @cant_stop:	Bringup/teardown can't be stopped at this step
 */
struct cpuhp_step {
	const char		*name;
	union {
		int		(*single)(unsigned int cpu);
		int		(*multi)(unsigned int cpu,
					 struct hlist_node *node);
	} startup;
	union {
		int		(*single)(unsigned int cpu);
		int		(*multi)(unsigned int cpu,
					 struct hlist_node *node);
	} teardown;
	struct hlist_head	list;
	bool			cant_stop;
	bool			multi_instance;
};

static DEFINE_MUTEX(cpuhp_state_mutex);
static struct cpuhp_step cpuhp_hp_states[];

static struct cpuhp_step *cpuhp_get_step(enum cpuhp_state state)
{
	return cpuhp_hp_states + state;
}

/**
 * cpuhp_invoke_callback _ Invoke the callbacks for a given state
 * @cpu:	The cpu for which the callback should be invoked
 * @state:	The state to do callbacks for
 * @bringup:	True if the bringup callback should be invoked
 * @node:	For multi-instance, do a single entry callback for install/remove
 * @lastp:	For multi-instance rollback, remember how far we got
 *
 * Called from cpu hotplug and from the state register machinery.
 */
static int cpuhp_invoke_callback(unsigned int cpu, enum cpuhp_state state,
				 bool bringup, struct hlist_node *node,
				 struct hlist_node **lastp)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	struct cpuhp_step *step = cpuhp_get_step(state);
	int (*cbm)(unsigned int cpu, struct hlist_node *node);
	int (*cb)(unsigned int cpu);
	int ret, cnt;

	if (st->fail == state) {
		st->fail = CPUHP_INVALID;

		if (!(bringup ? step->startup.single : step->teardown.single))
			return 0;

		return -EAGAIN;
	}

	if (!step->multi_instance) {
		WARN_ON_ONCE(lastp && *lastp);
		cb = bringup ? step->startup.single : step->teardown.single;
		if (!cb)
			return 0;
		trace_cpuhp_enter(cpu, st->target, state, cb);
		ret = cb(cpu);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		return ret;
	}
	cbm = bringup ? step->startup.multi : step->teardown.multi;
	if (!cbm)
		return 0;

	/* Single invocation for instance add/remove */
	if (node) {
		WARN_ON_ONCE(lastp && *lastp);
		trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
		ret = cbm(cpu, node);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		return ret;
	}

	/* State transition. Invoke on all instances */
	cnt = 0;
	hlist_for_each(node, &step->list) {
		if (lastp && node == *lastp)
			break;

		trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
		ret = cbm(cpu, node);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		if (ret) {
			if (!lastp)
				goto err;

			*lastp = node;
			return ret;
		}
		cnt++;
	}
	if (lastp)
		*lastp = NULL;
	return 0;
err:
	/* Rollback the instances if one failed */
	cbm = !bringup ? step->startup.multi : step->teardown.multi;
	if (!cbm)
		return ret;

	hlist_for_each(node, &step->list) {
		if (!cnt--)
			break;

		trace_cpuhp_multi_enter(cpu, st->target, state, cbm, node);
		ret = cbm(cpu, node);
		trace_cpuhp_exit(cpu, st->state, state, ret);
		/*
		 * Rollback must not fail,
		 */
		WARN_ON_ONCE(ret);
	}
	return ret;
}

#ifdef CONFIG_SMP
static bool cpuhp_is_ap_state(enum cpuhp_state state)
{
	/*
	 * The extra check for CPUHP_TEARDOWN_CPU is only for documentation
	 * purposes as that state is handled explicitly in cpu_down.
	 */
	return state > CPUHP_BRINGUP_CPU && state != CPUHP_TEARDOWN_CPU;
}

static inline void wait_for_ap_thread(struct cpuhp_cpu_state *st, bool bringup)
{
	struct completion *done = bringup ? &st->done_up : &st->done_down;
	wait_for_completion(done);
}

static inline void complete_ap_thread(struct cpuhp_cpu_state *st, bool bringup)
{
	struct completion *done = bringup ? &st->done_up : &st->done_down;
	complete(done);
}

/*
 * The former STARTING/DYING states, ran with IRQs disabled and must not fail.
 */
static bool cpuhp_is_atomic_state(enum cpuhp_state state)
{
	return CPUHP_AP_IDLE_DEAD <= state && state < CPUHP_AP_ONLINE;
}

/* Serializes the updates to cpu_online_mask, cpu_present_mask */
static DEFINE_MUTEX(cpu_add_remove_lock);
bool cpuhp_tasks_frozen;
EXPORT_SYMBOL_GPL(cpuhp_tasks_frozen);

/*
 * The following two APIs (cpu_maps_update_begin/done) must be used when
 * attempting to serialize the updates to cpu_online_mask & cpu_present_mask.
 */
void cpu_maps_update_begin(void)
{
	mutex_lock(&cpu_add_remove_lock);
}

void cpu_maps_update_done(void)
{
	mutex_unlock(&cpu_add_remove_lock);
}

/*
 * If set, cpu_up and cpu_down will return -EBUSY and do nothing.
 * Should always be manipulated under cpu_add_remove_lock
 */
static int cpu_hotplug_disabled;

#ifdef CONFIG_HOTPLUG_CPU

DEFINE_STATIC_PERCPU_RWSEM(cpu_hotplug_lock);

void cpus_read_lock(void)
{
	percpu_down_read(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_lock);

int cpus_read_trylock(void)
{
	return percpu_down_read_trylock(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_trylock);

void cpus_read_unlock(void)
{
	percpu_up_read(&cpu_hotplug_lock);
}
EXPORT_SYMBOL_GPL(cpus_read_unlock);

void cpus_write_lock(void)
{
	percpu_down_write(&cpu_hotplug_lock);
}

void cpus_write_unlock(void)
{
	percpu_up_write(&cpu_hotplug_lock);
}

void lockdep_assert_cpus_held(void)
{
	/*
	 * We can't have hotplug operations before userspace starts running,
	 * and some init codepaths will knowingly not take the hotplug lock.
	 * This is all valid, so mute lockdep until it makes sense to report
	 * unheld locks.
	 */
	if (system_state < SYSTEM_RUNNING)
		return;

	percpu_rwsem_assert_held(&cpu_hotplug_lock);
}

static void lockdep_acquire_cpus_lock(void)
{
	rwsem_acquire(&cpu_hotplug_lock.rw_sem.dep_map, 0, 0, _THIS_IP_);
}

static void lockdep_release_cpus_lock(void)
{
	rwsem_release(&cpu_hotplug_lock.rw_sem.dep_map, 1, _THIS_IP_);
}

/*
 * Wait for currently running CPU hotplug operations to complete (if any) and
 * disable future CPU hotplug (from sysfs). The 'cpu_add_remove_lock' protects
 * the 'cpu_hotplug_disabled' flag. The same lock is also acquired by the
 * hotplug path before performing hotplug operations. So acquiring that lock
 * guarantees mutual exclusion from any currently running hotplug operations.
 */
void cpu_hotplug_disable(void)
{
	cpu_maps_update_begin();
	cpu_hotplug_disabled++;
	cpu_maps_update_done();
}
EXPORT_SYMBOL_GPL(cpu_hotplug_disable);

static void __cpu_hotplug_enable(void)
{
	if (WARN_ONCE(!cpu_hotplug_disabled, "Unbalanced cpu hotplug enable\n"))
		return;
	cpu_hotplug_disabled--;
}

void cpu_hotplug_enable(void)
{
	cpu_maps_update_begin();
	__cpu_hotplug_enable();
	cpu_maps_update_done();
}
EXPORT_SYMBOL_GPL(cpu_hotplug_enable);

#else

static void lockdep_acquire_cpus_lock(void)
{
}

static void lockdep_release_cpus_lock(void)
{
}

#endif	/* CONFIG_HOTPLUG_CPU */

/*
 * Architectures that need SMT-specific errata handling during SMT hotplug
 * should override this.
 */
void __weak arch_smt_update(void) { }

#ifdef CONFIG_HOTPLUG_SMT
enum cpuhp_smt_control cpu_smt_control __read_mostly = CPU_SMT_ENABLED;

void __init cpu_smt_disable(bool force)
{
	if (!cpu_smt_possible())
		return;

	if (force) {
		pr_info("SMT: Force disabled\n");
		cpu_smt_control = CPU_SMT_FORCE_DISABLED;
	} else {
		pr_info("SMT: disabled\n");
		cpu_smt_control = CPU_SMT_DISABLED;
	}
}

/*
 * The decision whether SMT is supported can only be done after the full
 * CPU identification. Called from architecture code.
 */
void __init cpu_smt_check_topology(void)
{
	if (!topology_smt_supported())
		cpu_smt_control = CPU_SMT_NOT_SUPPORTED;
}

static int __init smt_cmdline_disable(char *str)
{
	cpu_smt_disable(str && !strcmp(str, "force"));
	return 0;
}
early_param("nosmt", smt_cmdline_disable);

static inline bool cpu_smt_allowed(unsigned int cpu)
{
	if (cpu_smt_control == CPU_SMT_ENABLED)
		return true;

	if (topology_is_primary_thread(cpu))
		return true;

	/*
	 * On x86 it's required to boot all logical CPUs at least once so
	 * that the init code can get a chance to set CR4.MCE on each
	 * CPU. Otherwise, a broadacasted MCE observing CR4.MCE=0b on any
	 * core will shutdown the machine.
	 */
	return !cpumask_test_cpu(cpu, &cpus_booted_once_mask);
}

/* Returns true if SMT is not supported of forcefully (irreversibly) disabled */
bool cpu_smt_possible(void)
{
	return cpu_smt_control != CPU_SMT_FORCE_DISABLED &&
		cpu_smt_control != CPU_SMT_NOT_SUPPORTED;
}
EXPORT_SYMBOL_GPL(cpu_smt_possible);
#else
static inline bool cpu_smt_allowed(unsigned int cpu) { return true; }
#endif

static inline enum cpuhp_state
cpuhp_set_state(struct cpuhp_cpu_state *st, enum cpuhp_state target)
{
	enum cpuhp_state prev_state = st->state;

	st->rollback = false;
	st->last = NULL;

	st->target = target;
	st->single = false;
	st->bringup = st->state < target;

	return prev_state;
}

static inline void
cpuhp_reset_state(struct cpuhp_cpu_state *st, enum cpuhp_state prev_state)
{
	st->rollback = true;

	/*
	 * If we have st->last we need to undo partial multi_instance of this
	 * state first. Otherwise start undo at the previous state.
	 */
	if (!st->last) {
		if (st->bringup)
			st->state--;
		else
			st->state++;
	}

	st->target = prev_state;
	st->bringup = !st->bringup;
}

/* Regular hotplug invocation of the AP hotplug thread */
static void __cpuhp_kick_ap(struct cpuhp_cpu_state *st)
{
	if (!st->single && st->state == st->target)
		return;

	st->result = 0;
	/*
	 * Make sure the above stores are visible before should_run becomes
	 * true. Paired with the mb() above in cpuhp_thread_fun()
	 */
	smp_mb();
	st->should_run = true;
	wake_up_process(st->thread);
	wait_for_ap_thread(st, st->bringup);
}

static int cpuhp_kick_ap(struct cpuhp_cpu_state *st, enum cpuhp_state target)
{
	enum cpuhp_state prev_state;
	int ret;

	prev_state = cpuhp_set_state(st, target);
	__cpuhp_kick_ap(st);
	if ((ret = st->result)) {
		cpuhp_reset_state(st, prev_state);
		__cpuhp_kick_ap(st);
	}

	return ret;
}

static int bringup_wait_for_ap(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);

	/* Wait for the CPU to reach CPUHP_AP_ONLINE_IDLE */
	wait_for_ap_thread(st, true);
	if (WARN_ON_ONCE((!cpu_online(cpu))))
		return -ECANCELED;

	/* Unpark the stopper thread and the hotplug thread of the target cpu */
	stop_machine_unpark(cpu);
	kthread_unpark(st->thread);

	/*
	 * SMT soft disabling on X86 requires to bring the CPU out of the
	 * BIOS 'wait for SIPI' state in order to set the CR4.MCE bit.  The
	 * CPU marked itself as booted_once in notify_cpu_starting() so the
	 * cpu_smt_allowed() check will now return false if this is not the
	 * primary sibling.
	 */
	if (!cpu_smt_allowed(cpu))
		return -ECANCELED;

	if (st->target <= CPUHP_AP_ONLINE_IDLE)
		return 0;

	return cpuhp_kick_ap(st, st->target);
}

static int bringup_cpu(unsigned int cpu)
{
	struct task_struct *idle = idle_thread_get(cpu);
	int ret;

	/*
	 * Some architectures have to walk the irq descriptors to
	 * setup the vector space for the cpu which comes online.
	 * Prevent irq alloc/free across the bringup.
	 */
	irq_lock_sparse();

	/* Arch-specific enabling code. */
	ret = __cpu_up(cpu, idle);
	irq_unlock_sparse();
	if (ret)
		return ret;
	return bringup_wait_for_ap(cpu);
}

/*
 * Hotplug state machine related functions
 */

static void undo_cpu_up(unsigned int cpu, struct cpuhp_cpu_state *st)
{
	for (st->state--; st->state > st->target; st->state--)
		cpuhp_invoke_callback(cpu, st->state, false, NULL, NULL);
}

static inline bool can_rollback_cpu(struct cpuhp_cpu_state *st)
{
	if (IS_ENABLED(CONFIG_HOTPLUG_CPU))
		return true;
	/*
	 * When CPU hotplug is disabled, then taking the CPU down is not
	 * possible because takedown_cpu() and the architecture and
	 * subsystem specific mechanisms are not available. So the CPU
	 * which would be completely unplugged again needs to stay around
	 * in the current state.
	 */
	return st->state <= CPUHP_BRINGUP_CPU;
}

static int cpuhp_up_callbacks(unsigned int cpu, struct cpuhp_cpu_state *st,
			      enum cpuhp_state target)
{
	enum cpuhp_state prev_state = st->state;
	int ret = 0;

	while (st->state < target) {
		st->state++;
		ret = cpuhp_invoke_callback(cpu, st->state, true, NULL, NULL);
		if (ret) {
			if (can_rollback_cpu(st)) {
				st->target = prev_state;
				undo_cpu_up(cpu, st);
			}
			break;
		}
	}
	return ret;
}

/*
 * The cpu hotplug threads manage the bringup and teardown of the cpus
 */
static void cpuhp_create(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);

	init_completion(&st->done_up);
	init_completion(&st->done_down);
}

static int cpuhp_should_run(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

	return st->should_run;
}

/*
 * Execute teardown/startup callbacks on the plugged cpu. Also used to invoke
 * callbacks when a state gets [un]installed at runtime.
 *
 * Each invocation of this function by the smpboot thread does a single AP
 * state callback.
 *
 * It has 3 modes of operation:
 *  - single: runs st->cb_state
 *  - up:     runs ++st->state, while st->state < st->target
 *  - down:   runs st->state--, while st->state > st->target
 *
 * When complete or on error, should_run is cleared and the completion is fired.
 */
static void cpuhp_thread_fun(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);
	bool bringup = st->bringup;
	enum cpuhp_state state;

	if (WARN_ON_ONCE(!st->should_run))
		return;

	/*
	 * ACQUIRE for the cpuhp_should_run() load of ->should_run. Ensures
	 * that if we see ->should_run we also see the rest of the state.
	 */
	smp_mb();

	/*
	 * The BP holds the hotplug lock, but we're now running on the AP,
	 * ensure that anybody asserting the lock is held, will actually find
	 * it so.
	 */
	lockdep_acquire_cpus_lock();
	cpuhp_lock_acquire(bringup);

	if (st->single) {
		state = st->cb_state;
		st->should_run = false;
	} else {
		if (bringup) {
			st->state++;
			state = st->state;
			st->should_run = (st->state < st->target);
			WARN_ON_ONCE(st->state > st->target);
		} else {
			state = st->state;
			st->state--;
			st->should_run = (st->state > st->target);
			WARN_ON_ONCE(st->state < st->target);
		}
	}

	WARN_ON_ONCE(!cpuhp_is_ap_state(state));

	if (cpuhp_is_atomic_state(state)) {
		local_irq_disable();
		st->result = cpuhp_invoke_callback(cpu, state, bringup, st->node, &st->last);
		local_irq_enable();

		/*
		 * STARTING/DYING must not fail!
		 */
		WARN_ON_ONCE(st->result);
	} else {
		st->result = cpuhp_invoke_callback(cpu, state, bringup, st->node, &st->last);
	}

	if (st->result) {
		/*
		 * If we fail on a rollback, we're up a creek without no
		 * paddle, no way forward, no way back. We loose, thanks for
		 * playing.
		 */
		WARN_ON_ONCE(st->rollback);
		st->should_run = false;
	}

	cpuhp_lock_release(bringup);
	lockdep_release_cpus_lock();

	if (!st->should_run)
		complete_ap_thread(st, bringup);
}

/* Invoke a single callback on a remote cpu */
static int
cpuhp_invoke_ap_callback(int cpu, enum cpuhp_state state, bool bringup,
			 struct hlist_node *node)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	int ret;

	if (!cpu_online(cpu))
		return 0;

	cpuhp_lock_acquire(false);
	cpuhp_lock_release(false);

	cpuhp_lock_acquire(true);
	cpuhp_lock_release(true);

	/*
	 * If we are up and running, use the hotplug thread. For early calls
	 * we invoke the thread function directly.
	 */
	if (!st->thread)
		return cpuhp_invoke_callback(cpu, state, bringup, node, NULL);

	st->rollback = false;
	st->last = NULL;

	st->node = node;
	st->bringup = bringup;
	st->cb_state = state;
	st->single = true;

	__cpuhp_kick_ap(st);

	/*
	 * If we failed and did a partial, do a rollback.
	 */
	if ((ret = st->result) && st->last) {
		st->rollback = true;
		st->bringup = !bringup;

		__cpuhp_kick_ap(st);
	}

	/*
	 * Clean up the leftovers so the next hotplug operation wont use stale
	 * data.
	 */
	st->node = st->last = NULL;
	return ret;
}

static int cpuhp_kick_ap_work(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	enum cpuhp_state prev_state = st->state;
	int ret;

	cpuhp_lock_acquire(false);
	cpuhp_lock_release(false);

	cpuhp_lock_acquire(true);
	cpuhp_lock_release(true);

	trace_cpuhp_enter(cpu, st->target, prev_state, cpuhp_kick_ap_work);
	ret = cpuhp_kick_ap(st, st->target);
	trace_cpuhp_exit(cpu, st->state, prev_state, ret);

	return ret;
}

static struct smp_hotplug_thread cpuhp_threads = {
	.store			= &cpuhp_state.thread,
	.create			= &cpuhp_create,
	.thread_should_run	= cpuhp_should_run,
	.thread_fn		= cpuhp_thread_fun,
	.thread_comm		= "cpuhp/%u",
	.selfparking		= true,
};

void __init cpuhp_threads_init(void)
{
	BUG_ON(smpboot_register_percpu_thread(&cpuhp_threads));
	kthread_unpark(this_cpu_read(cpuhp_state.thread));
}

#ifdef CONFIG_HOTPLUG_CPU
/**
 * clear_tasks_mm_cpumask - Safely clear tasks' mm_cpumask for a CPU
 * @cpu: a CPU id
 *
 * This function walks all processes, finds a valid mm struct for each one and
 * then clears a corresponding bit in mm's cpumask.  While this all sounds
 * trivial, there are various non-obvious corner cases, which this function
 * tries to solve in a safe manner.
 *
 * Also note that the function uses a somewhat relaxed locking scheme, so it may
 * be called only for an already offlined CPU.
 */
void clear_tasks_mm_cpumask(int cpu)
{
	struct task_struct *p;

	/*
	 * This function is called after the cpu is taken down and marked
	 * offline, so its not like new tasks will ever get this cpu set in
	 * their mm mask. -- Peter Zijlstra
	 * Thus, we may use rcu_read_lock() here, instead of grabbing
	 * full-fledged tasklist_lock.
	 */
	WARN_ON(cpu_online(cpu));
	rcu_read_lock();
	for_each_process(p) {
		struct task_struct *t;

		/*
		 * Main thread might exit, but other threads may still have
		 * a valid mm. Find one.
		 */
		t = find_lock_task_mm(p);
		if (!t)
			continue;
		cpumask_clear_cpu(cpu, mm_cpumask(t->mm));
		task_unlock(t);
	}
	rcu_read_unlock();
}

/* Take this CPU down. */
static int take_cpu_down(void *_param)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);
	enum cpuhp_state target = max((int)st->target, CPUHP_AP_OFFLINE);
	int err, cpu = smp_processor_id();
	int ret;

	/* Ensure this CPU doesn't handle any more interrupts. */
	err = __cpu_disable();
	if (err < 0)
		return err;

	/*
	 * We get here while we are in CPUHP_TEARDOWN_CPU state and we must not
	 * do this step again.
	 */
	WARN_ON(st->state != CPUHP_TEARDOWN_CPU);
	st->state--;
	/* Invoke the former CPU_DYING callbacks */
	for (; st->state > target; st->state--) {
		ret = cpuhp_invoke_callback(cpu, st->state, false, NULL, NULL);
		/*
		 * DYING must not fail!
		 */
		WARN_ON_ONCE(ret);
	}

	/* Give up timekeeping duties */
	tick_handover_do_timer();
	/* Remove CPU from timer broadcasting */
	tick_offline_cpu(cpu);
	/* Park the stopper thread */
	stop_machine_park(cpu);
	return 0;
}

static int takedown_cpu(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	int err;

	/* Park the smpboot threads */
	kthread_park(per_cpu_ptr(&cpuhp_state, cpu)->thread);

	/*
	 * Prevent irq alloc/free while the dying cpu reorganizes the
	 * interrupt affinities.
	 */
	irq_lock_sparse();

	/*
	 * So now all preempt/rcu users must observe !cpu_active().
	 */
	err = stop_machine_cpuslocked(take_cpu_down, NULL, cpumask_of(cpu));
	if (err) {
		/* CPU refused to die */
		irq_unlock_sparse();
		/* Unpark the hotplug thread so we can rollback there */
		kthread_unpark(per_cpu_ptr(&cpuhp_state, cpu)->thread);
		return err;
	}
	BUG_ON(cpu_online(cpu));

	/*
	 * The teardown callback for CPUHP_AP_SCHED_STARTING will have removed
	 * all runnable tasks from the CPU, there's only the idle task left now
	 * that the migration thread is done doing the stop_machine thing.
	 *
	 * Wait for the stop thread to go away.
	 */
	wait_for_ap_thread(st, false);
	BUG_ON(st->state != CPUHP_AP_IDLE_DEAD);

	/* Interrupts are moved away from the dying cpu, reenable alloc/free */
	irq_unlock_sparse();

	hotplug_cpu__broadcast_tick_pull(cpu);
	/* This actually kills the CPU. */
	__cpu_die(cpu);

	tick_cleanup_dead_cpu(cpu);
	rcutree_migrate_callbacks(cpu);
	return 0;
}

static void cpuhp_complete_idle_dead(void *arg)
{
	struct cpuhp_cpu_state *st = arg;

	complete_ap_thread(st, false);
}

void cpuhp_report_idle_dead(void)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

	BUG_ON(st->state != CPUHP_AP_OFFLINE);
	rcu_report_dead(smp_processor_id());
	st->state = CPUHP_AP_IDLE_DEAD;
	/*
	 * We cannot call complete after rcu_report_dead() so we delegate it
	 * to an online cpu.
	 */
	smp_call_function_single(cpumask_first(cpu_online_mask),
				 cpuhp_complete_idle_dead, st, 0);
}

static void undo_cpu_down(unsigned int cpu, struct cpuhp_cpu_state *st)
{
	for (st->state++; st->state < st->target; st->state++)
		cpuhp_invoke_callback(cpu, st->state, true, NULL, NULL);
}

static int cpuhp_down_callbacks(unsigned int cpu, struct cpuhp_cpu_state *st,
				enum cpuhp_state target)
{
	enum cpuhp_state prev_state = st->state;
	int ret = 0;

	for (; st->state > target; st->state--) {
		ret = cpuhp_invoke_callback(cpu, st->state, false, NULL, NULL);
		if (ret) {
			st->target = prev_state;
			if (st->state < prev_state)
				undo_cpu_down(cpu, st);
			break;
		}
	}
	return ret;
}

/* Requires cpu_add_remove_lock to be held */
static int __ref _cpu_down(unsigned int cpu, int tasks_frozen,
			   enum cpuhp_state target)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	int prev_state, ret = 0;

	if (num_online_cpus() == 1)
		return -EBUSY;

	if (!cpu_present(cpu))
		return -EINVAL;

	cpus_write_lock();

	cpuhp_tasks_frozen = tasks_frozen;

	prev_state = cpuhp_set_state(st, target);
	/*
	 * If the current CPU state is in the range of the AP hotplug thread,
	 * then we need to kick the thread.
	 */
	if (st->state > CPUHP_TEARDOWN_CPU) {
		st->target = max((int)target, CPUHP_TEARDOWN_CPU);
		ret = cpuhp_kick_ap_work(cpu);
		/*
		 * The AP side has done the error rollback already. Just
		 * return the error code..
		 */
		if (ret)
			goto out;

		/*
		 * We might have stopped still in the range of the AP hotplug
		 * thread. Nothing to do anymore.
		 */
		if (st->state > CPUHP_TEARDOWN_CPU)
			goto out;

		st->target = target;
	}
	/*
	 * The AP brought itself down to CPUHP_TEARDOWN_CPU. So we need
	 * to do the further cleanups.
	 */
	ret = cpuhp_down_callbacks(cpu, st, target);
	if (ret && st->state == CPUHP_TEARDOWN_CPU && st->state < prev_state) {
		cpuhp_reset_state(st, prev_state);
		__cpuhp_kick_ap(st);
	}

out:
	cpus_write_unlock();
	/*
	 * Do post unplug cleanup. This is still protected against
	 * concurrent CPU hotplug via cpu_add_remove_lock.
	 */
	lockup_detector_cleanup();
	arch_smt_update();
	return ret;
}

static int cpu_down_maps_locked(unsigned int cpu, enum cpuhp_state target)
{
	if (cpu_hotplug_disabled)
		return -EBUSY;
	return _cpu_down(cpu, 0, target);
}

static int do_cpu_down(unsigned int cpu, enum cpuhp_state target)
{
	int err;

	cpu_maps_update_begin();
	err = cpu_down_maps_locked(cpu, target);
	cpu_maps_update_done();
	return err;
}

int cpu_down(unsigned int cpu)
{
	return do_cpu_down(cpu, CPUHP_OFFLINE);
}
EXPORT_SYMBOL(cpu_down);

#else
#define takedown_cpu		NULL
#endif /*CONFIG_HOTPLUG_CPU*/

/**
 * notify_cpu_starting(cpu) - Invoke the callbacks on the starting CPU
 * @cpu: cpu that just started
 *
 * It must be called by the arch code on the new cpu, before the new cpu
 * enables interrupts and before the "boot" cpu returns from __cpu_up().
 */
void notify_cpu_starting(unsigned int cpu)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	enum cpuhp_state target = min((int)st->target, CPUHP_AP_ONLINE);
	int ret;

	rcu_cpu_starting(cpu);	/* Enables RCU usage on this CPU. */
	cpumask_set_cpu(cpu, &cpus_booted_once_mask);
	while (st->state < target) {
		st->state++;
		ret = cpuhp_invoke_callback(cpu, st->state, true, NULL, NULL);
		/*
		 * STARTING must not fail!
		 */
		WARN_ON_ONCE(ret);
	}
}

/*
 * Called from the idle task. Wake up the controlling task which brings the
 * stopper and the hotplug thread of the upcoming CPU up and then delegates
 * the rest of the online bringup to the hotplug thread.
 */
void cpuhp_online_idle(enum cpuhp_state state)
{
	struct cpuhp_cpu_state *st = this_cpu_ptr(&cpuhp_state);

	/* Happens for the boot cpu */
	if (state != CPUHP_AP_ONLINE_IDLE)
		return;

	st->state = CPUHP_AP_ONLINE_IDLE;
	complete_ap_thread(st, true);
}

/* Requires cpu_add_remove_lock to be held */
static int _cpu_up(unsigned int cpu, int tasks_frozen, enum cpuhp_state target)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
	struct task_struct *idle;
	int ret = 0;

	cpus_write_lock();

	if (!cpu_present(cpu)) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * The caller of do_cpu_up might have raced with another
	 * caller. Ignore it for now.
	 */
	if (st->state >= target)
		goto out;

	if (st->state == CPUHP_OFFLINE) {
		/* Let it fail before we try to bring the cpu up */
		idle = idle_thread_get(cpu);
		if (IS_ERR(idle)) {
			ret = PTR_ERR(idle);
			goto out;
		}
	}

	cpuhp_tasks_frozen = tasks_frozen;

	cpuhp_set_state(st, target);
	/*
	 * If the current CPU state is in the range of the AP hotplug thread,
	 * then we need to kick the thread once more.
	 */
	if (st->state > CPUHP_BRINGUP_CPU) {
		ret = cpuhp_kick_ap_work(cpu);
		/*
		 * The AP side has done the error rollback already. Just
		 * return the error code..
		 */
		if (ret)
			goto out;
	}

	/*
	 * Try to reach the target state. We max out on the BP at
	 * CPUHP_BRINGUP_CPU. After that the AP hotplug thread is
	 * responsible for bringing it up to the target state.
	 */
	target = min((int)target, CPUHP_BRINGUP_CPU);
	ret = cpuhp_up_callbacks(cpu, st, target);
out:
	cpus_write_unlock();
	arch_smt_update();
	return ret;
}

static int do_cpu_up(unsigned int cpu, enum cpuhp_state target)
{
	int err = 0;

	if (!cpu_possible(cpu)) {
		pr_err("can't online cpu %d because it is not configured as may-hotadd at boot time\n",
		       cpu);
#if defined(CONFIG_IA64)
		pr_err("please check additional_cpus= boot parameter\n");
#endif
		return -EINVAL;
	}

	err = try_online_node(cpu_to_node(cpu));
	if (err)
		return err;

	cpu_maps_update_begin();

	if (cpu_hotplug_disabled) {
		err = -EBUSY;
		goto out;
	}
	if (!cpu_smt_allowed(cpu)) {
		err = -EPERM;
		goto out;
	}

	err = _cpu_up(cpu, 0, target);
out:
	cpu_maps_update_done();
	return err;
}

int cpu_up(unsigned int cpu)
{
	return do_cpu_up(cpu, CPUHP_ONLINE);
}
EXPORT_SYMBOL_GPL(cpu_up);

#ifdef CONFIG_PM_SLEEP_SMP
static cpumask_var_t frozen_cpus;

int freeze_secondary_cpus(int primary)
{
	int cpu, error = 0;

	cpu_maps_update_begin();
	if (primary == -1) {
		primary = cpumask_first(cpu_online_mask);
		if (!housekeeping_cpu(primary, HK_FLAG_TIMER))
			primary = housekeeping_any_cpu(HK_FLAG_TIMER);
	} else {
		if (!cpu_online(primary))
			primary = cpumask_first(cpu_online_mask);
	}

	/*
	 * We take down all of the non-boot CPUs in one shot to avoid races
	 * with the userspace trying to use the CPU hotplug at the same time
	 */
	cpumask_clear(frozen_cpus);

	pr_info("Disabling non-boot CPUs ...\n");
	for_each_online_cpu(cpu) {
		if (cpu == primary)
			continue;

		if (pm_wakeup_pending()) {
			pr_info("Wakeup pending. Abort CPU freeze\n");
			error = -EBUSY;
			break;
		}

		trace_suspend_resume(TPS("CPU_OFF"), cpu, true);
		error = _cpu_down(cpu, 1, CPUHP_OFFLINE);
		trace_suspend_resume(TPS("CPU_OFF"), cpu, false);
		if (!error)
			cpumask_set_cpu(cpu, frozen_cpus);
		else {
			pr_err("Error taking CPU%d down: %d\n", cpu, error);
			break;
		}
	}

	if (!error)
		BUG_ON(num_online_cpus() > 1);
	else
		pr_err("Non-boot CPUs are not disabled\n");

	/*
	 * Make sure the CPUs won't be enabled by someone else. We need to do
	 * this even in case of failure as all disable_nonboot_cpus() users are
	 * supposed to do enable_nonboot_cpus() on the failure path.
	 */
	cpu_hotplug_disabled++;

	cpu_maps_update_done();
	return error;
}

void __weak arch_enable_nonboot_cpus_begin(void)
{
}

void __weak arch_enable_nonboot_cpus_end(void)
{
}

void enable_nonboot_cpus(void)
{
	int cpu, error;

	/* Allow everyone to use the CPU hotplug again */
	cpu_maps_update_begin();
	__cpu_hotplug_enable();
	if (cpumask_empty(frozen_cpus))
		goto out;

	pr_info("Enabling non-boot CPUs ...\n");

	arch_enable_nonboot_cpus_begin();

	for_each_cpu(cpu, frozen_cpus) {
		trace_suspend_resume(TPS("CPU_ON"), cpu, true);
		error = _cpu_up(cpu, 1, CPUHP_ONLINE);
		trace_suspend_resume(TPS("CPU_ON"), cpu, false);
		if (!error) {
			pr_info("CPU%d is up\n", cpu);
			continue;
		}
		pr_warn("Error taking CPU%d up: %d\n", cpu, error);
	}

	arch_enable_nonboot_cpus_end();

	cpumask_clear(frozen_cpus);
out:
	cpu_maps_update_done();
}

static int __init alloc_frozen_cpus(void)
{
	if (!alloc_cpumask_var(&frozen_cpus, GFP_KERNEL|__GFP_ZERO))
		return -ENOMEM;
	return 0;
}
core_initcall(alloc_frozen_cpus);

/*
 * When callbacks for CPU hotplug notifications are being executed, we must
 * ensure that the state of the system with respect to the tasks being frozen
 * or not, as reported by the notification, remains unchanged *throughout the
 * duration* of the execution of the callbacks.
 * Hence we need to prevent the freezer from racing with regular CPU hotplug.
 *
 * This synchronization is implemented by mutually excluding regular CPU
 * hotplug and Suspend/Hibernate call paths by hooking onto the Suspend/
 * Hibernate notifications.
 */
static int
cpu_hotplug_pm_callback(struct notifier_block *nb,
			unsigned long action, void *ptr)
{
	switch (action) {

	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
		cpu_hotplug_disable();
		break;

	case PM_POST_SUSPEND:
	case PM_POST_HIBERNATION:
		cpu_hotplug_enable();
		break;

	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}


static int __init cpu_hotplug_pm_sync_init(void)
{
	/*
	 * cpu_hotplug_pm_callback has higher priority than x86
	 * bsp_pm_callback which depends on cpu_hotplug_pm_callback
	 * to disable cpu hotplug to avoid cpu hotplug race.
	 */
	pm_notifier(cpu_hotplug_pm_callback, 0);
	return 0;
}
core_initcall(cpu_hotplug_pm_sync_init);

#endif /* CONFIG_PM_SLEEP_SMP */

int __boot_cpu_id;

#endif /* CONFIG_SMP */

/* Boot processor state steps */
static struct cpuhp_step cpuhp_hp_states[] = {
	[CPUHP_OFFLINE] = {
		.name			= "offline",
		.startup.single		= NULL,
		.teardown.single	= NULL,
	},
#ifdef CONFIG_SMP
	[CPUHP_CREATE_THREADS]= {
		.name			= "threads:prepare",
		.startup.single		= smpboot_create_threads,
		.teardown.single	= NULL,
		.cant_stop		= true,
	},
	[CPUHP_PERF_PREPARE] = {
		.name			= "perf:prepare",
		.startup.single		= perf_event_init_cpu,
		.teardown.single	= perf_event_exit_cpu,
	},
	[CPUHP_WORKQUEUE_PREP] = {
		.name			= "workqueue:prepare",
		.startup.single		= workqueue_prepare_cpu,
		.teardown.single	= NULL,
	},
	[CPUHP_HRTIMERS_PREPARE] = {
		.name			= "hrtimers:prepare",
		.startup.single		= hrtimers_prepare_cpu,
		.teardown.single	= hrtimers_dead_cpu,
	},
	[CPUHP_SMPCFD_PREPARE] = {
		.name			= "smpcfd:prepare",
		.startup.single		= smpcfd_prepare_cpu,
		.teardown.single	= smpcfd_dead_cpu,
	},
	[CPUHP_RELAY_PREPARE] = {
		.name			= "relay:prepare",
		.startup.single		= relay_prepare_cpu,
		.teardown.single	= NULL,
	},
	[CPUHP_SLAB_PREPARE] = {
		.name			= "slab:prepare",
		.startup.single		= slab_prepare_cpu,
		.teardown.single	= slab_dead_cpu,
	},
	[CPUHP_RCUTREE_PREP] = {
		.name			= "RCU/tree:prepare",
		.startup.single		= rcutree_prepare_cpu,
		.teardown.single	= rcutree_dead_cpu,
	},
	/*
	 * On the tear-down path, timers_dead_cpu() must be invoked
	 * before blk_mq_queue_reinit_notify() from notify_dead(),
	 * otherwise a RCU stall occurs.
	 */
	[CPUHP_TIMERS_PREPARE] = {
		.name			= "timers:prepare",
		.startup.single		= timers_prepare_cpu,
		.teardown.single	= timers_dead_cpu,
	},
	/* Kicks the plugged cpu into life */
	[CPUHP_BRINGUP_CPU] = {
		.name			= "cpu:bringup",
		.startup.single		= bringup_cpu,
		.teardown.single	= NULL,
		.cant_stop		= true,
	},
	/* Final state before CPU kills itself */
	[CPUHP_AP_IDLE_DEAD] = {
		.name			= "idle:dead",
	},
	/*
	 * Last state before CPU enters the idle loop to die. Transient state
	 * for synchronization.
	 */
	[CPUHP_AP_OFFLINE] = {
		.name			= "ap:offline",
		.cant_stop		= true,
	},
	/* First state is scheduler control. Interrupts are disabled */
	[CPUHP_AP_SCHED_STARTING] = {
		.name			= "sched:starting",
		.startup.single		= sched_cpu_starting,
		.teardown.single	= sched_cpu_dying,
	},
	[CPUHP_AP_RCUTREE_DYING] = {
		.name			= "RCU/tree:dying",
		.startup.single		= NULL,
		.teardown.single	= rcutree_dying_cpu,
	},
	[CPUHP_AP_SMPCFD_DYING] = {
		.name			= "smpcfd:dying",
		.startup.single		= NULL,
		.teardown.single	= smpcfd_dying_cpu,
	},
	/* Entry state on starting. Interrupts enabled from here on. Transient
	 * state for synchronsization */
	[CPUHP_AP_ONLINE] = {
		.name			= "ap:online",
	},
	/*
	 * Handled on controll processor until the plugged processor manages
	 * this itself.
	 */
	[CPUHP_TEARDOWN_CPU] = {
		.name			= "cpu:teardown",
		.startup.single		= NULL,
		.teardown.single	= takedown_cpu,
		.cant_stop		= true,
	},
	/* Handle smpboot threads park/unpark */
	[CPUHP_AP_SMPBOOT_THREADS] = {
		.name			= "smpboot/threads:online",
		.startup.single		= smpboot_unpark_threads,
		.teardown.single	= smpboot_park_threads,
	},
	[CPUHP_AP_IRQ_AFFINITY_ONLINE] = {
		.name			= "irq/affinity:online",
		.startup.single		= irq_affinity_online_cpu,
		.teardown.single	= NULL,
	},
	[CPUHP_AP_PERF_ONLINE] = {
		.name			= "perf:online",
		.startup.single		= perf_event_init_cpu,
		.teardown.single	= perf_event_exit_cpu,
	},
	[CPUHP_AP_WATCHDOG_ONLINE] = {
		.name			= "lockup_detector:online",
		.startup.single		= lockup_detector_online_cpu,
		.teardown.single	= lockup_detector_offline_cpu,
	},
	[CPUHP_AP_WORKQUEUE_ONLINE] = {
		.name			= "workqueue:online",
		.startup.single		= workqueue_online_cpu,
		.teardown.single	= workqueue_offline_cpu,
	},
	[CPUHP_AP_RCUTREE_ONLINE] = {
		.name			= "RCU/tree:online",
		.startup.single		= rcutree_online_cpu,
		.teardown.single	= rcutree_offline_cpu,
	},
#endif
	/*
	 * The dynamically registered state space is here
	 */

#ifdef CONFIG_SMP
	/* Last state is scheduler control setting the cpu active */
	[CPUHP_AP_ACTIVE] = {
		.name			= "sched:active",
		.startup.single		= sched_cpu_activate,
		.teardown.single	= sched_cpu_deactivate,
	},
#endif

	/* CPU is fully up and running. */
	[CPUHP_ONLINE] = {
		.name			= "online",
		.startup.single		= NULL,
		.teardown.single	= NULL,
	},
};

/* Sanity check for callbacks */
static int cpuhp_cb_check(enum cpuhp_state state)
{
	if (state <= CPUHP_OFFLINE || state >= CPUHP_ONLINE)
		return -EINVAL;
	return 0;
}

/*
 * Returns a free for dynamic slot assignment of the Online state. The states
 * are protected by the cpuhp_slot_states mutex and an empty slot is identified
 * by having no name assigned.
 */
static int cpuhp_reserve_state(enum cpuhp_state state)
{
	enum cpuhp_state i, end;
	struct cpuhp_step *step;

	switch (state) {
	case CPUHP_AP_ONLINE_DYN:
		step = cpuhp_hp_states + CPUHP_AP_ONLINE_DYN;
		end = CPUHP_AP_ONLINE_DYN_END;
		break;
	case CPUHP_BP_PREPARE_DYN:
		step = cpuhp_hp_states + CPUHP_BP_PREPARE_DYN;
		end = CPUHP_BP_PREPARE_DYN_END;
		break;
	default:
		return -EINVAL;
	}

	for (i = state; i <= end; i++, step++) {
		if (!step->name)
			return i;
	}
	WARN(1, "No more dynamic states available for CPU hotplug\n");
	return -ENOSPC;
}

static int cpuhp_store_callbacks(enum cpuhp_state state, const char *name,
				 int (*startup)(unsigned int cpu),
				 int (*teardown)(unsigned int cpu),
				 bool multi_instance)
{
	/* (Un)Install the callbacks for further cpu hotplug operations */
	struct cpuhp_step *sp;
	int ret = 0;

	/*
	 * If name is NULL, then the state gets removed.
	 *
	 * CPUHP_AP_ONLINE_DYN and CPUHP_BP_PREPARE_DYN are handed out on
	 * the first allocation from these dynamic ranges, so the removal
	 * would trigger a new allocation and clear the wrong (already
	 * empty) state, leaving the callbacks of the to be cleared state
	 * dangling, which causes wreckage on the next hotplug operation.
	 */
	if (name && (state == CPUHP_AP_ONLINE_DYN ||
		     state == CPUHP_BP_PREPARE_DYN)) {
		ret = cpuhp_reserve_state(state);
		if (ret < 0)
			return ret;
		state = ret;
	}
	sp = cpuhp_get_step(state);
	if (name && sp->name)
		return -EBUSY;

	sp->startup.single = startup;
	sp->teardown.single = teardown;
	sp->name = name;
	sp->multi_instance = multi_instance;
	INIT_HLIST_HEAD(&sp->list);
	return ret;
}

static void *cpuhp_get_teardown_cb(enum cpuhp_state state)
{
	return cpuhp_get_step(state)->teardown.single;
}

/*
 * Call the startup/teardown function for a step either on the AP or
 * on the current CPU.
 */
static int cpuhp_issue_call(int cpu, enum cpuhp_state state, bool bringup,
			    struct hlist_node *node)
{
	struct cpuhp_step *sp = cpuhp_get_step(state);
	int ret;

	/*
	 * If there's nothing to do, we done.
	 * Relies on the union for multi_instance.
	 */
	if ((bringup && !sp->startup.single) ||
	    (!bringup && !sp->teardown.single))
		return 0;
	/*
	 * The non AP bound callbacks can fail on bringup. On teardown
	 * e.g. module removal we crash for now.
	 */
#ifdef CONFIG_SMP
	if (cpuhp_is_ap_state(state))
		ret = cpuhp_invoke_ap_callback(cpu, state, bringup, node);
	else
		ret = cpuhp_invoke_callback(cpu, state, bringup, node, NULL);
#else
	ret = cpuhp_invoke_callback(cpu, state, bringup, node, NULL);
#endif
	BUG_ON(ret && !bringup);
	return ret;
}

/*
 * Called from __cpuhp_setup_state on a recoverable failure.
 *
 * Note: The teardown callbacks for rollback are not allowed to fail!
 */
static void cpuhp_rollback_install(int failedcpu, enum cpuhp_state state,
				   struct hlist_node *node)
{
	int cpu;

	/* Roll back the already executed steps on the other cpus */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpu >= failedcpu)
			break;

		/* Did we invoke the startup call on that cpu ? */
		if (cpustate >= state)
			cpuhp_issue_call(cpu, state, false, node);
	}
}

int __cpuhp_state_add_instance_cpuslocked(enum cpuhp_state state,
					  struct hlist_node *node,
					  bool invoke)
{
	struct cpuhp_step *sp;
	int cpu;
	int ret;

	lockdep_assert_cpus_held();

	sp = cpuhp_get_step(state);
	if (sp->multi_instance == false)
		return -EINVAL;

	mutex_lock(&cpuhp_state_mutex);

	if (!invoke || !sp->startup.multi)
		goto add_node;

	/*
	 * Try to call the startup callback for each present cpu
	 * depending on the hotplug state of the cpu.
	 */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpustate < state)
			continue;

		ret = cpuhp_issue_call(cpu, state, true, node);
		if (ret) {
			if (sp->teardown.multi)
				cpuhp_rollback_install(cpu, state, node);
			goto unlock;
		}
	}
add_node:
	ret = 0;
	hlist_add_head(node, &sp->list);
unlock:
	mutex_unlock(&cpuhp_state_mutex);
	return ret;
}

int __cpuhp_state_add_instance(enum cpuhp_state state, struct hlist_node *node,
			       bool invoke)
{
	int ret;

	cpus_read_lock();
	ret = __cpuhp_state_add_instance_cpuslocked(state, node, invoke);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(__cpuhp_state_add_instance);

/**
 * __cpuhp_setup_state_cpuslocked - Setup the callbacks for an hotplug machine state
 * @state:		The state to setup
 * @invoke:		If true, the startup function is invoked for cpus where
 *			cpu state >= @state
 * @startup:		startup callback function
 * @teardown:		teardown callback function
 * @multi_instance:	State is set up for multiple instances which get
 *			added afterwards.
 *
 * The caller needs to hold cpus read locked while calling this function.
 * Returns:
 *   On success:
 *      Positive state number if @state is CPUHP_AP_ONLINE_DYN
 *      0 for all other states
 *   On failure: proper (negative) error code
 */
int __cpuhp_setup_state_cpuslocked(enum cpuhp_state state,
				   const char *name, bool invoke,
				   int (*startup)(unsigned int cpu),
				   int (*teardown)(unsigned int cpu),
				   bool multi_instance)
{
	int cpu, ret = 0;
	bool dynstate;

	lockdep_assert_cpus_held();

	if (cpuhp_cb_check(state) || !name)
		return -EINVAL;

	mutex_lock(&cpuhp_state_mutex);

	ret = cpuhp_store_callbacks(state, name, startup, teardown,
				    multi_instance);

	dynstate = state == CPUHP_AP_ONLINE_DYN;
	if (ret > 0 && dynstate) {
		state = ret;
		ret = 0;
	}

	if (ret || !invoke || !startup)
		goto out;

	/*
	 * Try to call the startup callback for each present cpu
	 * depending on the hotplug state of the cpu.
	 */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpustate < state)
			continue;

		ret = cpuhp_issue_call(cpu, state, true, NULL);
		if (ret) {
			if (teardown)
				cpuhp_rollback_install(cpu, state, NULL);
			cpuhp_store_callbacks(state, NULL, NULL, NULL, false);
			goto out;
		}
	}
out:
	mutex_unlock(&cpuhp_state_mutex);
	/*
	 * If the requested state is CPUHP_AP_ONLINE_DYN, return the
	 * dynamically allocated state in case of success.
	 */
	if (!ret && dynstate)
		return state;
	return ret;
}
EXPORT_SYMBOL(__cpuhp_setup_state_cpuslocked);

int __cpuhp_setup_state(enum cpuhp_state state,
			const char *name, bool invoke,
			int (*startup)(unsigned int cpu),
			int (*teardown)(unsigned int cpu),
			bool multi_instance)
{
	int ret;

	cpus_read_lock();
	ret = __cpuhp_setup_state_cpuslocked(state, name, invoke, startup,
					     teardown, multi_instance);
	cpus_read_unlock();
	return ret;
}
EXPORT_SYMBOL(__cpuhp_setup_state);

int __cpuhp_state_remove_instance(enum cpuhp_state state,
				  struct hlist_node *node, bool invoke)
{
	struct cpuhp_step *sp = cpuhp_get_step(state);
	int cpu;

	BUG_ON(cpuhp_cb_check(state));

	if (!sp->multi_instance)
		return -EINVAL;

	cpus_read_lock();
	mutex_lock(&cpuhp_state_mutex);

	if (!invoke || !cpuhp_get_teardown_cb(state))
		goto remove;
	/*
	 * Call the teardown callback for each present cpu depending
	 * on the hotplug state of the cpu. This function is not
	 * allowed to fail currently!
	 */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpustate >= state)
			cpuhp_issue_call(cpu, state, false, node);
	}

remove:
	hlist_del(node);
	mutex_unlock(&cpuhp_state_mutex);
	cpus_read_unlock();

	return 0;
}
EXPORT_SYMBOL_GPL(__cpuhp_state_remove_instance);

/**
 * __cpuhp_remove_state_cpuslocked - Remove the callbacks for an hotplug machine state
 * @state:	The state to remove
 * @invoke:	If true, the teardown function is invoked for cpus where
 *		cpu state >= @state
 *
 * The caller needs to hold cpus read locked while calling this function.
 * The teardown callback is currently not allowed to fail. Think
 * about module removal!
 */
void __cpuhp_remove_state_cpuslocked(enum cpuhp_state state, bool invoke)
{
	struct cpuhp_step *sp = cpuhp_get_step(state);
	int cpu;

	BUG_ON(cpuhp_cb_check(state));

	lockdep_assert_cpus_held();

	mutex_lock(&cpuhp_state_mutex);
	if (sp->multi_instance) {
		WARN(!hlist_empty(&sp->list),
		     "Error: Removing state %d which has instances left.\n",
		     state);
		goto remove;
	}

	if (!invoke || !cpuhp_get_teardown_cb(state))
		goto remove;

	/*
	 * Call the teardown callback for each present cpu depending
	 * on the hotplug state of the cpu. This function is not
	 * allowed to fail currently!
	 */
	for_each_present_cpu(cpu) {
		struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, cpu);
		int cpustate = st->state;

		if (cpustate >= state)
			cpuhp_issue_call(cpu, state, false, NULL);
	}
remove:
	cpuhp_store_callbacks(state, NULL, NULL, NULL, false);
	mutex_unlock(&cpuhp_state_mutex);
}
EXPORT_SYMBOL(__cpuhp_remove_state_cpuslocked);

void __cpuhp_remove_state(enum cpuhp_state state, bool invoke)
{
	cpus_read_lock();
	__cpuhp_remove_state_cpuslocked(state, invoke);
	cpus_read_unlock();
}
EXPORT_SYMBOL(__cpuhp_remove_state);

#if defined(CONFIG_SYSFS) && defined(CONFIG_HOTPLUG_CPU)
static ssize_t show_cpuhp_state(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);

	return sprintf(buf, "%d\n", st->state);
}
static DEVICE_ATTR(state, 0444, show_cpuhp_state, NULL);

static ssize_t write_cpuhp_target(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);
	struct cpuhp_step *sp;
	int target, ret;

	ret = kstrtoint(buf, 10, &target);
	if (ret)
		return ret;

#ifdef CONFIG_CPU_HOTPLUG_STATE_CONTROL
	if (target < CPUHP_OFFLINE || target > CPUHP_ONLINE)
		return -EINVAL;
#else
	if (target != CPUHP_OFFLINE && target != CPUHP_ONLINE)
		return -EINVAL;
#endif

	ret = lock_device_hotplug_sysfs();
	if (ret)
		return ret;

	mutex_lock(&cpuhp_state_mutex);
	sp = cpuhp_get_step(target);
	ret = !sp->name || sp->cant_stop ? -EINVAL : 0;
	mutex_unlock(&cpuhp_state_mutex);
	if (ret)
		goto out;

	if (st->state < target)
		ret = do_cpu_up(dev->id, target);
	else
		ret = do_cpu_down(dev->id, target);
out:
	unlock_device_hotplug();
	return ret ? ret : count;
}

static ssize_t show_cpuhp_target(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);

	return sprintf(buf, "%d\n", st->target);
}
static DEVICE_ATTR(target, 0644, show_cpuhp_target, write_cpuhp_target);


static ssize_t write_cpuhp_fail(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);
	struct cpuhp_step *sp;
	int fail, ret;

	ret = kstrtoint(buf, 10, &fail);
	if (ret)
		return ret;

	if (fail < CPUHP_OFFLINE || fail > CPUHP_ONLINE)
		return -EINVAL;

	/*
	 * Cannot fail STARTING/DYING callbacks.
	 */
	if (cpuhp_is_atomic_state(fail))
		return -EINVAL;

	/*
	 * Cannot fail anything that doesn't have callbacks.
	 */
	mutex_lock(&cpuhp_state_mutex);
	sp = cpuhp_get_step(fail);
	if (!sp->startup.single && !sp->teardown.single)
		ret = -EINVAL;
	mutex_unlock(&cpuhp_state_mutex);
	if (ret)
		return ret;

	st->fail = fail;

	return count;
}

static ssize_t show_cpuhp_fail(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cpuhp_cpu_state *st = per_cpu_ptr(&cpuhp_state, dev->id);

	return sprintf(buf, "%d\n", st->fail);
}

static DEVICE_ATTR(fail, 0644, show_cpuhp_fail, write_cpuhp_fail);

static struct attribute *cpuhp_cpu_attrs[] = {
	&dev_attr_state.attr,
	&dev_attr_target.attr,
	&dev_attr_fail.attr,
	NULL
};

static const struct attribute_group cpuhp_cpu_attr_group = {
	.attrs = cpuhp_cpu_attrs,
	.name = "hotplug",
	NULL
};

static ssize_t show_cpuhp_states(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	ssize_t cur, res = 0;
	int i;

	mutex_lock(&cpuhp_state_mutex);
	for (i = CPUHP_OFFLINE; i <= CPUHP_ONLINE; i++) {
		struct cpuhp_step *sp = cpuhp_get_step(i);

		if (sp->name) {
			cur = sprintf(buf, "%3d: %s\n", i, sp->name);
			buf += cur;
			res += cur;
		}
	}
	mutex_unlock(&cpuhp_state_mutex);
	return res;
}
static DEVICE_ATTR(states, 0444, show_cpuhp_states, NULL);

static struct attribute *cpuhp_cpu_root_attrs[] = {
	&dev_attr_states.attr,
	NULL
};

static const struct attribute_group cpuhp_cpu_root_attr_group = {
	.attrs = cpuhp_cpu_root_attrs,
	.name = "hotplug",
	NULL
};

#ifdef CONFIG_HOTPLUG_SMT

static void cpuhp_offline_cpu_device(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	dev->offline = true;
	/* Tell user space about the state change */
	kobject_uevent(&dev->kobj, KOBJ_OFFLINE);
}

static void cpuhp_online_cpu_device(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	dev->offline = false;
	/* Tell user space about the state change */
	kobject_uevent(&dev->kobj, KOBJ_ONLINE);
}

int cpuhp_smt_disable(enum cpuhp_smt_control ctrlval)
{
	int cpu, ret = 0;

	cpu_maps_update_begin();
	for_each_online_cpu(cpu) {
		if (topology_is_primary_thread(cpu))
			continue;
		ret = cpu_down_maps_locked(cpu, CPUHP_OFFLINE);
		if (ret)
			break;
		/*
		 * As this needs to hold the cpu maps lock it's impossible
		 * to call device_offline() because that ends up calling
		 * cpu_down() which takes cpu maps lock. cpu maps lock
		 * needs to be held as this might race against in kernel
		 * abusers of the hotplug machinery (thermal management).
		 *
		 * So nothing would update device:offline state. That would
		 * leave the sysfs entry stale and prevent onlining after
		 * smt control has been changed to 'off' again. This is
		 * called under the sysfs hotplug lock, so it is properly
		 * serialized against the regular offline usage.
		 */
		cpuhp_offline_cpu_device(cpu);
	}
	if (!ret)
		cpu_smt_control = ctrlval;
	cpu_maps_update_done();
	return ret;
}

int cpuhp_smt_enable(void)
{
	int cpu, ret = 0;

	cpu_maps_update_begin();
	cpu_smt_control = CPU_SMT_ENABLED;
	for_each_present_cpu(cpu) {
		/* Skip online CPUs and CPUs on offline nodes */
		if (cpu_online(cpu) || !node_online(cpu_to_node(cpu)))
			continue;
		ret = _cpu_up(cpu, 0, CPUHP_ONLINE);
		if (ret)
			break;
		/* See comment in cpuhp_smt_disable() */
		cpuhp_online_cpu_device(cpu);
	}
	cpu_maps_update_done();
	return ret;
}


static ssize_t
__store_smt_control(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	int ctrlval, ret;

	if (sysfs_streq(buf, "on"))
		ctrlval = CPU_SMT_ENABLED;
	else if (sysfs_streq(buf, "off"))
		ctrlval = CPU_SMT_DISABLED;
	else if (sysfs_streq(buf, "forceoff"))
		ctrlval = CPU_SMT_FORCE_DISABLED;
	else
		return -EINVAL;

	if (cpu_smt_control == CPU_SMT_FORCE_DISABLED)
		return -EPERM;

	if (cpu_smt_control == CPU_SMT_NOT_SUPPORTED)
		return -ENODEV;

	ret = lock_device_hotplug_sysfs();
	if (ret)
		return ret;

	if (ctrlval != cpu_smt_control) {
		switch (ctrlval) {
		case CPU_SMT_ENABLED:
			ret = cpuhp_smt_enable();
			break;
		case CPU_SMT_DISABLED:
		case CPU_SMT_FORCE_DISABLED:
			ret = cpuhp_smt_disable(ctrlval);
			break;
		}
	}

	unlock_device_hotplug();
	return ret ? ret : count;
}

#else /* !CONFIG_HOTPLUG_SMT */
static ssize_t
__store_smt_control(struct device *dev, struct device_attribute *attr,
		    const char *buf, size_t count)
{
	return -ENODEV;
}
#endif /* CONFIG_HOTPLUG_SMT */

static const char *smt_states[] = {
	[CPU_SMT_ENABLED]		= "on",
	[CPU_SMT_DISABLED]		= "off",
	[CPU_SMT_FORCE_DISABLED]	= "forceoff",
	[CPU_SMT_NOT_SUPPORTED]		= "notsupported",
	[CPU_SMT_NOT_IMPLEMENTED]	= "notimplemented",
};

static ssize_t
show_smt_control(struct device *dev, struct device_attribute *attr, char *buf)
{
	const char *state = smt_states[cpu_smt_control];

	return snprintf(buf, PAGE_SIZE - 2, "%s\n", state);
}

static ssize_t
store_smt_control(struct device *dev, struct device_attribute *attr,
		  const char *buf, size_t count)
{
	return __store_smt_control(dev, attr, buf, count);
}
static DEVICE_ATTR(control, 0644, show_smt_control, store_smt_control);

static ssize_t
show_smt_active(struct device *dev, struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE - 2, "%d\n", sched_smt_active());
}
static DEVICE_ATTR(active, 0444, show_smt_active, NULL);

static struct attribute *cpuhp_smt_attrs[] = {
	&dev_attr_control.attr,
	&dev_attr_active.attr,
	NULL
};

static const struct attribute_group cpuhp_smt_attr_group = {
	.attrs = cpuhp_smt_attrs,
	.name = "smt",
	NULL
};

static int __init cpu_smt_sysfs_init(void)
{
	return sysfs_create_group(&cpu_subsys.dev_root->kobj,
				  &cpuhp_smt_attr_group);
}

static int __init cpuhp_sysfs_init(void)
{
	int cpu, ret;

	ret = cpu_smt_sysfs_init();
	if (ret)
		return ret;

	ret = sysfs_create_group(&cpu_subsys.dev_root->kobj,
				 &cpuhp_cpu_root_attr_group);
	if (ret)
		return ret;

	for_each_possible_cpu(cpu) {
		struct device *dev = get_cpu_device(cpu);

		if (!dev)
			continue;
		ret = sysfs_create_group(&dev->kobj, &cpuhp_cpu_attr_group);
		if (ret)
			return ret;
	}
	return 0;
}
device_initcall(cpuhp_sysfs_init);
#endif /* CONFIG_SYSFS && CONFIG_HOTPLUG_CPU */

/*
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x)	[x+1][0] = (1UL << (x))
#define MASK_DECLARE_2(x)	MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x)	MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x)	MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {

	MASK_DECLARE_8(0),	MASK_DECLARE_8(8),
	MASK_DECLARE_8(16),	MASK_DECLARE_8(24),
#if BITS_PER_LONG > 32
	MASK_DECLARE_8(32),	MASK_DECLARE_8(40),
	MASK_DECLARE_8(48),	MASK_DECLARE_8(56),
#endif
};
EXPORT_SYMBOL_GPL(cpu_bit_bitmap);

const DECLARE_BITMAP(cpu_all_bits, NR_CPUS) = CPU_BITS_ALL;
EXPORT_SYMBOL(cpu_all_bits);

#ifdef CONFIG_INIT_ALL_POSSIBLE
struct cpumask __cpu_possible_mask __read_mostly
	= {CPU_BITS_ALL};
#else
struct cpumask __cpu_possible_mask __read_mostly;
#endif
EXPORT_SYMBOL(__cpu_possible_mask);

struct cpumask __cpu_online_mask __read_mostly;
EXPORT_SYMBOL(__cpu_online_mask);

struct cpumask __cpu_present_mask __read_mostly;
EXPORT_SYMBOL(__cpu_present_mask);

struct cpumask __cpu_active_mask __read_mostly;
EXPORT_SYMBOL(__cpu_active_mask);

atomic_t __num_online_cpus __read_mostly;
EXPORT_SYMBOL(__num_online_cpus);

void init_cpu_present(const struct cpumask *src)
{
	cpumask_copy(&__cpu_present_mask, src);
}

void init_cpu_possible(const struct cpumask *src)
{
	cpumask_copy(&__cpu_possible_mask, src);
}

void init_cpu_online(const struct cpumask *src)
{
	cpumask_copy(&__cpu_online_mask, src);
}

void set_cpu_online(unsigned int cpu, bool online)
{
	/*
	 * atomic_inc/dec() is required to handle the horrid abuse of this
	 * function by the reboot and kexec code which invoke it from
	 * IPI/NMI broadcasts when shutting down CPUs. Invocation from
	 * regular CPU hotplug is properly serialized.
	 *
	 * Note, that the fact that __num_online_cpus is of type atomic_t
	 * does not protect readers which are not serialized against
	 * concurrent hotplug operations.
	 */
	if (online) {
		if (!cpumask_test_and_set_cpu(cpu, &__cpu_online_mask))
			atomic_inc(&__num_online_cpus);
	} else {
		if (cpumask_test_and_clear_cpu(cpu, &__cpu_online_mask))
			atomic_dec(&__num_online_cpus);
	}
}

/*
 * Activate the first processor.
 */
void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();

	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);

#ifdef CONFIG_SMP
	__boot_cpu_id = cpu;
#endif
}

/*
 * Must be called _AFTER_ setting up the per_cpu areas
 */
void __init boot_cpu_hotplug_init(void)
{
#ifdef CONFIG_SMP
	cpumask_set_cpu(smp_processor_id(), &cpus_booted_once_mask);
#endif
	this_cpu_write(cpuhp_state.state, CPUHP_ONLINE);
}

enum cpu_mitigations cpu_mitigations __ro_after_init = CPU_MITIGATIONS_AUTO;

static int __init mitigations_parse_cmdline(char *arg)
{
	if (!strcmp(arg, "off"))
		cpu_mitigations = CPU_MITIGATIONS_OFF;
	else if (!strcmp(arg, "auto"))
		cpu_mitigations = CPU_MITIGATIONS_AUTO;
	else if (!strcmp(arg, "auto,nosmt"))
		cpu_mitigations = CPU_MITIGATIONS_AUTO_NOSMT;
	else
		pr_crit("Unsupported mitigations=%s, system may still be vulnerable\n",
			arg);

	return 0;
}
early_param("mitigations", mitigations_parse_cmdline);
return 0 ;

}
/* Generate assembler source containing symbol information
 *
 * Copyright 2002       by Kai Germaschewski
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 *
 * Usage: nm -n vmlinux | scripts/kallsyms [--all-symbols] > symbols.S
 *
 *      Table compression uses all the unused char codes on the symbols and
 *  maps these to the most used substrings (tokens). For instance, it might
 *  map char code 0xF7 to represent "write_" and then in every symbol where
 *  "write_" appears it can be replaced by 0xF7, saving 5 bytes.
 *      The used codes themselves are also placed in the table so that the
 *  decompresion can work without "special cases".
 *      Applied to kernel symbols, this usually produces a compression ratio
 *  of about 50%.
 *
 */
struct sym_entry {
	unsigned long long addr;
	unsigned int len;
	unsigned int start_pos;
	unsigned char *sym;
	unsigned int percpu_absolute;
};

struct addr_range {
	const char *start_sym, *end_sym;
	unsigned long long start, end;
};

static unsigned long long _text;
static unsigned long long relative_base;
static struct addr_range text_ranges[] = {
	{ "_stext",     "_etext"     },
	{ "_sinittext", "_einittext" },
};
#define text_range_text     (&text_ranges[0])
#define text_range_inittext (&text_ranges[1])

static struct addr_range percpu_range = {
	"__per_cpu_start", "__per_cpu_end", -1ULL, 0
};

static struct sym_entry *table;
static unsigned int table_size, table_cnt;
static int all_symbols = 0;
static int absolute_percpu = 0;
static int base_relative = 0;

static int token_profit[0x10000];

/* the table that holds the result of the compression */
static unsigned char best_table[256][2];
static unsigned char best_table_len[256];


static void usage(void)
{
	fprintf(stderr, "Usage: kallsyms [--all-symbols] "
			"[--base-relative] < in.map > out.S\n");
	exit(1);
}

/*
 * This ignores the intensely annoying "mapping symbols" found
 * in ARM ELF files: $a, $t and $d.
 */
static int is_arm_mapping_symbol(const char *str)
{
	return str[0] == '$' && strchr("axtd", str[1])
	       && (str[2] == '\0' || str[2] == '.');
}

static int check_symbol_range(const char *sym, unsigned long long addr,
			      struct addr_range *ranges, int entries)
{
	size_t i;
	struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (strcmp(sym, ar->start_sym) == 0) {
			ar->start = addr;
			return 0;
		} else if (strcmp(sym, ar->end_sym) == 0) {
			ar->end = addr;
			return 0;
		}
	}

	return 1;
}

static int read_symbol(FILE *in, struct sym_entry *s)
{
	char sym[500], stype;
	int rc;

	rc = fscanf(in, "%llx %c %499s\n", &s->addr, &stype, sym);
	if (rc != 3) {
		if (rc != EOF && fgets(sym, 500, in) == NULL)
			fprintf(stderr, "Read error or end of file.\n");
		return -1;
	}
	if (strlen(sym) >= KSYM_NAME_LEN) {
		fprintf(stderr, "Symbol %s too long for kallsyms (%zu >= %d).\n"
				"Please increase KSYM_NAME_LEN both in kernel and kallsyms.c\n",
			sym, strlen(sym), KSYM_NAME_LEN);
		return -1;
	}

	/* Ignore most absolute/undefined (?) symbols. */
	if (strcmp(sym, "_text") == 0)
		_text = s->addr;
	else if (check_symbol_range(sym, s->addr, text_ranges,
				    ARRAY_SIZE(text_ranges)) == 0)
		/* nothing to do */;
	else if (toupper(stype) == 'A')
	{
		/* Keep these useful absolute symbols */
		if (strcmp(sym, "__kernel_syscall_via_break") &&
		    strcmp(sym, "__kernel_syscall_via_epc") &&
		    strcmp(sym, "__kernel_sigtramp") &&
		    strcmp(sym, "__gp"))
			return -1;

	}
	else if (toupper(stype) == 'U' ||
		 is_arm_mapping_symbol(sym))
		return -1;
	/* exclude also MIPS ELF local symbols ($L123 instead of .L123) */
	else if (sym[0] == '$')
		return -1;
	/* exclude debugging symbols */
	else if (stype == 'N' || stype == 'n')
		return -1;
	/* exclude s390 kasan local symbols */
	else if (!strncmp(sym, ".LASANPC", 8))
		return -1;

	/* include the type field in the symbol name, so that it gets
	 * compressed together */
	s->len = strlen(sym) + 1;
	s->sym = malloc(s->len + 1);
	if (!s->sym) {
		fprintf(stderr, "kallsyms failure: "
			"unable to allocate required amount of memory\n");
		exit(EXIT_FAILURE);
	}
	strcpy((char *)s->sym + 1, sym);
	s->sym[0] = stype;

	s->percpu_absolute = 0;

	/* Record if we've found __per_cpu_start/end. */
	check_symbol_range(sym, s->addr, &percpu_range, 1);

	return 0;
}

static int symbol_in_range(struct sym_entry *s, struct addr_range *ranges,
			   int entries)
{
	size_t i;
	struct addr_range *ar;

	for (i = 0; i < entries; ++i) {
		ar = &ranges[i];

		if (s->addr >= ar->start && s->addr <= ar->end)
			return 1;
	}

	return 0;
}

static int symbol_valid(struct sym_entry *s)
{
	/* Symbols which vary between passes.  Passes 1 and 2 must have
	 * identical symbol lists.  The kallsyms_* symbols below are only added
	 * after pass 1, they would be included in pass 2 when --all-symbols is
	 * specified so exclude them to get a stable symbol list.
	 */
	static char *special_symbols[] = {
		"kallsyms_addresses",
		"kallsyms_offsets",
		"kallsyms_relative_base",
		"kallsyms_num_syms",
		"kallsyms_names",
		"kallsyms_markers",
		"kallsyms_token_table",
		"kallsyms_token_index",

	/* Exclude linker generated symbols which vary between passes */
		"_SDA_BASE_",		/* ppc */
		"_SDA2_BASE_",		/* ppc */
		NULL };

	static char *special_prefixes[] = {
		"__crc_",		/* modversions */
		"__efistub_",		/* arm64 EFI stub namespace */
		NULL };

	static char *special_suffixes[] = {
		"_veneer",		/* arm */
		"_from_arm",		/* arm */
		"_from_thumb",		/* arm */
		NULL };

	int i;
	char *sym_name = (char *)s->sym + 1;

	/* if --all-symbols is not specified, then symbols outside the text
	 * and inittext sections are discarded */
	if (!all_symbols) {
		if (symbol_in_range(s, text_ranges,
				    ARRAY_SIZE(text_ranges)) == 0)
			return 0;
		/* Corner case.  Discard any symbols with the same value as
		 * _etext _einittext; they can move between pass 1 and 2 when
		 * the kallsyms data are added.  If these symbols move then
		 * they may get dropped in pass 2, which breaks the kallsyms
		 * rules.
		 */
		if ((s->addr == text_range_text->end &&
				strcmp(sym_name,
				       text_range_text->end_sym)) ||
		    (s->addr == text_range_inittext->end &&
				strcmp(sym_name,
				       text_range_inittext->end_sym)))
			return 0;
	}

	/* Exclude symbols which vary between passes. */
	for (i = 0; special_symbols[i]; i++)
		if (strcmp(sym_name, special_symbols[i]) == 0)
			return 0;

	for (i = 0; special_prefixes[i]; i++) {
		int l = strlen(special_prefixes[i]);

		if (l <= strlen(sym_name) &&
		    strncmp(sym_name, special_prefixes[i], l) == 0)
			return 0;
	}

	for (i = 0; special_suffixes[i]; i++) {
		int l = strlen(sym_name) - strlen(special_suffixes[i]);

		if (l >= 0 && strcmp(sym_name + l, special_suffixes[i]) == 0)
			return 0;
	}

	return 1;
}

static void read_map(FILE *in)
{
	while (!feof(in)) {
		if (table_cnt >= table_size) {
			table_size += 10000;
			table = realloc(table, sizeof(*table) * table_size);
			if (!table) {
				fprintf(stderr, "out of memory\n");
				exit (1);
			}
		}
		if (read_symbol(in, &table[table_cnt]) == 0) {
			table[table_cnt].start_pos = table_cnt;
			table_cnt++;
		}
	}
}

static void output_label(char *label)
{
	printf(".globl %s\n", label);
	printf("\tALGN\n");
	printf("%s:\n", label);
}

/* uncompress a compressed symbol. When this function is called, the best table
 * might still be compressed itself, so the function needs to be recursive */
static int expand_symbol(unsigned char *data, int len, char *result)
{
	int c, rlen, total=0;

	while (len) {
		c = *data;
		/* if the table holds a single char that is the same as the one
		 * we are looking for, then end the search */
		if (best_table[c][0]==c && best_table_len[c]==1) {
			*result++ = c;
			total++;
		} else {
			/* if not, recurse and expand */
			rlen = expand_symbol(best_table[c], best_table_len[c], result);
			total += rlen;
			result += rlen;
		}
		data++;
		len--;
	}
	*result=0;

	return total;
}

static int symbol_absolute(struct sym_entry *s)
{
	return s->percpu_absolute;
}

static void write_src(void)
{
	unsigned int i, k, off;
	unsigned int best_idx[256];
	unsigned int *markers;
	char buf[KSYM_NAME_LEN];

	printf("#include <asm/bitsperlong.h>\n");
	printf("#if BITS_PER_LONG == 64\n");
	printf("#define PTR .quad\n");
	printf("#define ALGN .balign 8\n");
	printf("#else\n");
	printf("#define PTR .long\n");
	printf("#define ALGN .balign 4\n");
	printf("#endif\n");

	printf("\t.section .rodata, \"a\"\n");

	/* Provide proper symbols relocatability by their relativeness
	 * to a fixed anchor point in the runtime image, either '_text'
	 * for absolute address tables, in which case the linker will
	 * emit the final addresses at build time. Otherwise, use the
	 * offset relative to the lowest value encountered of all relative
	 * symbols, and emit non-relocatable fixed offsets that will be fixed
	 * up at runtime.
	 *
	 * The symbol names cannot be used to construct normal symbol
	 * references as the list of symbols contains symbols that are
	 * declared static and are private to their .o files.  This prevents
	 * .tmp_kallsyms.o or any other object from referencing them.
	 */
	if (!base_relative)
		output_label("kallsyms_addresses");
	else
		output_label("kallsyms_offsets");

	for (i = 0; i < table_cnt; i++) {
		if (base_relative) {
			long long offset;
			int overflow;

			if (!absolute_percpu) {
				offset = table[i].addr - relative_base;
				overflow = (offset < 0 || offset > UINT_MAX);
			} else if (symbol_absolute(&table[i])) {
				offset = table[i].addr;
				overflow = (offset < 0 || offset > INT_MAX);
			} else {
				offset = relative_base - table[i].addr - 1;
				overflow = (offset < INT_MIN || offset >= 0);
			}
			if (overflow) {
				fprintf(stderr, "kallsyms failure: "
					"%s symbol value %#llx out of range in relative mode\n",
					symbol_absolute(&table[i]) ? "absolute" : "relative",
					table[i].addr);
				exit(EXIT_FAILURE);
			}
			printf("\t.long\t%#x\n", (int)offset);
		} else if (!symbol_absolute(&table[i])) {
			if (_text <= table[i].addr)
				printf("\tPTR\t_text + %#llx\n",
					table[i].addr - _text);
			else
				printf("\tPTR\t_text - %#llx\n",
					_text - table[i].addr);
		} else {
			printf("\tPTR\t%#llx\n", table[i].addr);
		}
	}
	printf("\n");

	if (base_relative) {
		output_label("kallsyms_relative_base");
		printf("\tPTR\t_text - %#llx\n", _text - relative_base);
		printf("\n");
	}

	output_label("kallsyms_num_syms");
	printf("\t.long\t%u\n", table_cnt);
	printf("\n");

	/* table of offset markers, that give the offset in the compressed stream
	 * every 256 symbols */
	markers = malloc(sizeof(unsigned int) * ((table_cnt + 255) / 256));
	if (!markers) {
		fprintf(stderr, "kallsyms failure: "
			"unable to allocate required memory\n");
		exit(EXIT_FAILURE);
	}

	output_label("kallsyms_names");
	off = 0;
	for (i = 0; i < table_cnt; i++) {
		if ((i & 0xFF) == 0)
			markers[i >> 8] = off;

		printf("\t.byte 0x%02x", table[i].len);
		for (k = 0; k < table[i].len; k++)
			printf(", 0x%02x", table[i].sym[k]);
		printf("\n");

		off += table[i].len + 1;
	}
	printf("\n");

	output_label("kallsyms_markers");
	for (i = 0; i < ((table_cnt + 255) >> 8); i++)
		printf("\t.long\t%u\n", markers[i]);
	printf("\n");

	free(markers);

	output_label("kallsyms_token_table");
	off = 0;
	for (i = 0; i < 256; i++) {
		best_idx[i] = off;
		expand_symbol(best_table[i], best_table_len[i], buf);
		printf("\t.asciz\t\"%s\"\n", buf);
		off += strlen(buf) + 1;
	}
	printf("\n");

	output_label("kallsyms_token_index");
	for (i = 0; i < 256; i++)
		printf("\t.short\t%d\n", best_idx[i]);
	printf("\n");
}


/* table lookup compression functions */

/* count all the possible tokens in a symbol */
static void learn_symbol(unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]++;
}

/* decrease the count for all the possible tokens in a symbol */
static void forget_symbol(unsigned char *symbol, int len)
{
	int i;

	for (i = 0; i < len - 1; i++)
		token_profit[ symbol[i] + (symbol[i + 1] << 8) ]--;
}

/* remove all the invalid symbols from the table and do the initial token count */
static void build_initial_tok_table(void)
{
	unsigned int i, pos;

	pos = 0;
	for (i = 0; i < table_cnt; i++) {
		if ( symbol_valid(&table[i]) ) {
			if (pos != i)
				table[pos] = table[i];
			learn_symbol(table[pos].sym, table[pos].len);
			pos++;
		}
	}
	table_cnt = pos;
}

static void *find_token(unsigned char *str, int len, unsigned char *token)
{
	int i;

	for (i = 0; i < len - 1; i++) {
		if (str[i] == token[0] && str[i+1] == token[1])
			return &str[i];
	}
	return NULL;
}

/* replace a given token in all the valid symbols. Use the sampled symbols
 * to update the counts */
static void compress_symbols(unsigned char *str, int idx)
{
	unsigned int i, len, size;
	unsigned char *p1, *p2;

	for (i = 0; i < table_cnt; i++) {

		len = table[i].len;
		p1 = table[i].sym;

		/* find the token on the symbol */
		p2 = find_token(p1, len, str);
		if (!p2) continue;

		/* decrease the counts for this symbol's tokens */
		forget_symbol(table[i].sym, len);

		size = len;

		do {
			*p2 = idx;
			p2++;
			size -= (p2 - p1);
			memmove(p2, p2 + 1, size);
			p1 = p2;
			len--;

			if (size < 2) break;

			/* find the token on the symbol */
			p2 = find_token(p1, size, str);

		} while (p2);

		table[i].len = len;

		/* increase the counts for this symbol's new tokens */
		learn_symbol(table[i].sym, len);
	}
}

/* search the token with the maximum profit */
static int find_best_token(void)
{
	int i, best, bestprofit;

	bestprofit=-10000;
	best = 0;

	for (i = 0; i < 0x10000; i++) {
		if (token_profit[i] > bestprofit) {
			best = i;
			bestprofit = token_profit[i];
		}
	}
	return best;
}

/* this is the core of the algorithm: calculate the "best" table */
static void optimize_result(void)
{
	int i, best;

	/* using the '\0' symbol last allows compress_symbols to use standard
	 * fast string functions */
	for (i = 255; i >= 0; i--) {

		/* if this table slot is empty (it is not used by an actual
		 * original char code */
		if (!best_table_len[i]) {

			/* find the token with the best profit value */
			best = find_best_token();
			if (token_profit[best] == 0)
				break;

			/* place it in the "best" table */
			best_table_len[i] = 2;
			best_table[i][0] = best & 0xFF;
			best_table[i][1] = (best >> 8) & 0xFF;

			/* replace this token in all the valid symbols */
			compress_symbols(best_table[i], i);
		}
	}
}

/* start by placing the symbols that are actually used on the table */
static void insert_real_symbols_in_table(void)
{
	unsigned int i, j, c;

	for (i = 0; i < table_cnt; i++) {
		for (j = 0; j < table[i].len; j++) {
			c = table[i].sym[j];
			best_table[c][0]=c;
			best_table_len[c]=1;
		}
	}
}

static void optimize_token_table(void)
{
	build_initial_tok_table();

	insert_real_symbols_in_table();

	/* When valid symbol is not registered, exit to error */
	if (!table_cnt) {
		fprintf(stderr, "No valid symbol.\n");
		exit(1);
	}

	optimize_result();
}

/* guess for "linker script provide" symbol */
static int may_be_linker_script_provide_symbol(const struct sym_entry *se)
{
	const char *symbol = (char *)se->sym + 1;
	int len = se->len - 1;

	if (len < 8)
		return 0;

	if (symbol[0] != '_' || symbol[1] != '_')
		return 0;

	/* __start_XXXXX */
	if (!memcmp(symbol + 2, "start_", 6))
		return 1;

	/* __stop_XXXXX */
	if (!memcmp(symbol + 2, "stop_", 5))
		return 1;

	/* __end_XXXXX */
	if (!memcmp(symbol + 2, "end_", 4))
		return 1;

	/* __XXXXX_start */
	if (!memcmp(symbol + len - 6, "_start", 6))
		return 1;

	/* __XXXXX_end */
	if (!memcmp(symbol + len - 4, "_end", 4))
		return 1;

	return 0;
}

static int prefix_underscores_count(const char *str)
{
	const char *tail = str;

	while (*tail == '_')
		tail++;

	return tail - str;
}

static int compare_symbols(const void *a, const void *b)
{
	const struct sym_entry *sa;
	const struct sym_entry *sb;
	int wa, wb;

	sa = a;
	sb = b;

	/* sort by address first */
	if (sa->addr > sb->addr)
		return 1;
	if (sa->addr < sb->addr)
		return -1;

	/* sort by "weakness" type */
	wa = (sa->sym[0] == 'w') || (sa->sym[0] == 'W');
	wb = (sb->sym[0] == 'w') || (sb->sym[0] == 'W');
	if (wa != wb)
		return wa - wb;

	/* sort by "linker script provide" type */
	wa = may_be_linker_script_provide_symbol(sa);
	wb = may_be_linker_script_provide_symbol(sb);
	if (wa != wb)
		return wa - wb;

	/* sort by the number of prefix underscores */
	wa = prefix_underscores_count((const char *)sa->sym + 1);
	wb = prefix_underscores_count((const char *)sb->sym + 1);
	if (wa != wb)
		return wa - wb;

	/* sort by initial order, so that other symbols are left undisturbed */
	return sa->start_pos - sb->start_pos;
}

static void sort_symbols(void)
{
	qsort(table, table_cnt, sizeof(struct sym_entry), compare_symbols);
}

static void make_percpus_absolute(void)
{
	unsigned int i;

	for (i = 0; i < table_cnt; i++)
		if (symbol_in_range(&table[i], &percpu_range, 1)) {
			/*
			 * Keep the 'A' override for percpu symbols to
			 * ensure consistent behavior compared to older
			 * versions of this tool.
			 */
			table[i].sym[0] = 'A';
			table[i].percpu_absolute = 1;
		}
}

/* find the minimum non-absolute symbol address */
static void record_relative_base(void)
{
	unsigned int i;

	relative_base = -1ULL;
	for (i = 0; i < table_cnt; i++)
		if (!symbol_absolute(&table[i]) &&
		    table[i].addr < relative_base)
			relative_base = table[i].addr;
}

int Applied_to_kernel_symbols(int argc, char **argv)
{
	if (argc >= 2) {
		int i;
		for (i = 1; i < argc; i++) {
			if(strcmp(argv[i], "--all-symbols") == 0)
				all_symbols = 1;
			else if (strcmp(argv[i], "--absolute-percpu") == 0)
				absolute_percpu = 1;
			else if (strcmp(argv[i], "--base-relative") == 0)
				base_relative = 1;
			else
				usage();
		}
	} else if (argc != 1)
		usage();

	read_map(stdin);
	if (absolute_percpu)
		make_percpus_absolute();
	if (base_relative)
		record_relative_base();
	sort_symbols();
	optimize_token_table();
	write_src();

	return 0;
}
/*
 * Unloved program to convert a binary on stdin to a C include on stdout
 *
 * Jan 2019 Shishov Michael  <fandim16k@gmail.com>
 */
int convert_to_C(int argc, char *argv[])
{
	int ch, total = 0;

	if (argc > 1)
		printf("const char %s[] %s=\n",
			argv[1], argc > 2 ? argv[2] : "");

	do {
		printf("\t\"");
		while ((ch = getchar()) != EOF) {
			total++;
			printf("\\x%02x", ch);
			if (total % 16 == 0)
				break;
		}
		printf("\"\n");
	} while (ch != EOF);

	if (argc > 1)
		printf("\t;\n\n#include <linux/types.h>\n\nconst size_t %s_size = %d;\n",
		       argv[1], total);

	return 0;
}

int FILE_SYSTEM=[10] {

  Home , Computer,Network, System ,Hardware


};  // Main Folders 


/*
 * Copyright 2012-2016 by the PaX Team <pageexec@freemail.hu>
 * Copyright 2016 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * This gcc plugin helps generate a little bit of entropy from program state,
 * used throughout the uptime of the kernel. Here is an instrumentation example:
 *
 * before:
 * void __latent_entropy test(int argc, char *argv[])
 * {
 *	if (argc <= 1)
 *		printf("%s: no command arguments :(\n", *argv);
 *	else
 *		printf("%s: %d command arguments!\n", *argv, args - 1);
 * }
 *
 * after:
 * void __latent_entropy test(int argc, char *argv[])
 * {
 *	// latent_entropy_execute() 1.
 *	unsigned long local_entropy;
 *	// init_local_entropy() 1.
 *	void *local_entropy_frameaddr;
 *	// init_local_entropy() 3.
 *	unsigned long tmp_latent_entropy;
 *
 *	// init_local_entropy() 2.
 *	local_entropy_frameaddr = __builtin_frame_address(0);
 *	local_entropy = (unsigned long) local_entropy_frameaddr;
 *
 *	// init_local_entropy() 4.
 *	tmp_latent_entropy = latent_entropy;
 *	// init_local_entropy() 5.
 *	local_entropy ^= tmp_latent_entropy;
 *
 *	// latent_entropy_execute() 3.
 *	if (argc <= 1) {
 *		// perturb_local_entropy()
 *		local_entropy += 4623067384293424948;
 *		printf("%s: no command arguments :(\n", *argv);
 *		// perturb_local_entropy()
 *	} else {
 *		local_entropy ^= 3896280633962944730;
 *		printf("%s: %d command arguments!\n", *argv, args - 1);
 *	}
 *
 *	// latent_entropy_execute() 4.
 *	tmp_latent_entropy = rol(tmp_latent_entropy, local_entropy);
 *	latent_entropy = tmp_latent_entropy;
 * }
 *
 * TODO:
 * - add ipa pass to identify not explicitly marked candidate functions
 * - mix in more program state (function arguments/return values,
 *   loop variables, etc)
 * - more instrumentation control via attribute parameters
 *
 * BUGS:
 * - none known
 *
 * Options:
 * -fplugin-arg-latent_entropy_plugin-disable
 *
 * Attribute: __attribute__((latent_entropy))
 *  The latent_entropy gcc attribute can be only on functions and variables.
 *  If it is on a function then the plugin will instrument it. If the attribute
 *  is on a variable then the plugin will initialize it with a random value.
 *  The variable must be an integer, an integer array type or a structure
 *  with integer fields.
 */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static GTY(()) tree latent_entropy_decl;

static struct plugin_info latent_entropy_plugin_info = {
	.version	= "201606141920vanilla",
	.help		= "disable\tturn off latent entropy instrumentation\n",
};

static unsigned HOST_WIDE_INT seed;
/*
 * get_random_seed() (this is a GCC function) generates the seed.
 * This is a simple random generator without any cryptographic security because
 * the entropy doesn't come from here.
 */
static unsigned HOST_WIDE_INT get_random_const(void)
{
	unsigned int i;
	unsigned HOST_WIDE_INT ret = 0;

	for (i = 0; i < 8 * sizeof(ret); i++) {
		ret = (ret << 1) | (seed & 1);
		seed >>= 1;
		if (ret & 1)
			seed ^= 0xD800000000000000ULL;
	}

	return ret;
}

static tree tree_get_random_const(tree type)
{
	unsigned long long mask;

	mask = 1ULL << (TREE_INT_CST_LOW(TYPE_SIZE(type)) - 1);
	mask = 2 * (mask - 1) + 1;

	if (TYPE_UNSIGNED(type))
		return build_int_cstu(type, mask & get_random_const());
	return build_int_cst(type, mask & get_random_const());
}

static tree handle_latent_entropy_attribute(tree *node, tree name,
						tree args __unused,
						int flags __unused,
						bool *no_add_attrs)
{
	tree type;
#if BUILDING_GCC_VERSION <= 4007
	VEC(constructor_elt, gc) *vals;
#else
	vec<constructor_elt, va_gc> *vals;
#endif

	switch (TREE_CODE(*node)) {
	default:
		*no_add_attrs = true;
		error("%qE attribute only applies to functions and variables",
			name);
		break;

	case VAR_DECL:
		if (DECL_INITIAL(*node)) {
			*no_add_attrs = true;
			error("variable %qD with %qE attribute must not be initialized",
				*node, name);
			break;
		}

		if (!TREE_STATIC(*node)) {
			*no_add_attrs = true;
			error("variable %qD with %qE attribute must not be local",
				*node, name);
			break;
		}

		type = TREE_TYPE(*node);
		switch (TREE_CODE(type)) {
		default:
			*no_add_attrs = true;
			error("variable %qD with %qE attribute must be an integer or a fixed length integer array type or a fixed sized structure with integer fields",
				*node, name);
			break;

		case RECORD_TYPE: {
			tree fld, lst = TYPE_FIELDS(type);
			unsigned int nelt = 0;

			for (fld = lst; fld; nelt++, fld = TREE_CHAIN(fld)) {
				tree fieldtype;

				fieldtype = TREE_TYPE(fld);
				if (TREE_CODE(fieldtype) == INTEGER_TYPE)
					continue;

				*no_add_attrs = true;
				error("structure variable %qD with %qE attribute has a non-integer field %qE",
					*node, name, fld);
				break;
			}

			if (fld)
				break;

#if BUILDING_GCC_VERSION <= 4007
			vals = VEC_alloc(constructor_elt, gc, nelt);
#else
			vec_alloc(vals, nelt);
#endif

			for (fld = lst; fld; fld = TREE_CHAIN(fld)) {
				tree random_const, fld_t = TREE_TYPE(fld);

				random_const = tree_get_random_const(fld_t);
				CONSTRUCTOR_APPEND_ELT(vals, fld, random_const);
			}

			/* Initialize the fields with random constants */
			DECL_INITIAL(*node) = build_constructor(type, vals);
			break;
		}

		/* Initialize the variable with a random constant */
		case INTEGER_TYPE:
			DECL_INITIAL(*node) = tree_get_random_const(type);
			break;

		case ARRAY_TYPE: {
			tree elt_type, array_size, elt_size;
			unsigned int i, nelt;
			HOST_WIDE_INT array_size_int, elt_size_int;

			elt_type = TREE_TYPE(type);
			elt_size = TYPE_SIZE_UNIT(TREE_TYPE(type));
			array_size = TYPE_SIZE_UNIT(type);

			if (TREE_CODE(elt_type) != INTEGER_TYPE || !array_size
				|| TREE_CODE(array_size) != INTEGER_CST) {
				*no_add_attrs = true;
				error("array variable %qD with %qE attribute must be a fixed length integer array type",
					*node, name);
				break;
			}

			array_size_int = TREE_INT_CST_LOW(array_size);
			elt_size_int = TREE_INT_CST_LOW(elt_size);
			nelt = array_size_int / elt_size_int;

#if BUILDING_GCC_VERSION <= 4007
			vals = VEC_alloc(constructor_elt, gc, nelt);
#else
			vec_alloc(vals, nelt);
#endif

			for (i = 0; i < nelt; i++) {
				tree cst = size_int(i);
				tree rand_cst = tree_get_random_const(elt_type);

				CONSTRUCTOR_APPEND_ELT(vals, cst, rand_cst);
			}

			/*
			 * Initialize the elements of the array with random
			 * constants
			 */
			DECL_INITIAL(*node) = build_constructor(type, vals);
			break;
		}
		}
		break;

	case FUNCTION_DECL:
		break;
	}

	return NULL_TREE;
}

static struct attribute_spec latent_entropy_attr = { };

static void register_attributes(void *event_data __unused, void *data __unused)
{
	latent_entropy_attr.name		= "latent_entropy";
	latent_entropy_attr.decl_required	= true;
	latent_entropy_attr.handler		= handle_latent_entropy_attribute;

	register_attribute(&latent_entropy_attr);
}

static bool latent_entropy_gate(void)
{
	tree list;

	/* don't bother with noreturn functions for now */
	if (TREE_THIS_VOLATILE(current_function_decl))
		return false;

	/* gcc-4.5 doesn't discover some trivial noreturn functions */
	if (EDGE_COUNT(EXIT_BLOCK_PTR_FOR_FN(cfun)->preds) == 0)
		return false;

	list = DECL_ATTRIBUTES(current_function_decl);
	return lookup_attribute("latent_entropy", list) != NULL_TREE;
}

static tree create_var(tree type, const char *name)
{
	tree var;

	var = create_tmp_var(type, name);
	add_referenced_var(var);
	mark_sym_for_renaming(var);
	return var;
}

/*
 * Set up the next operation and its constant operand to use in the latent
 * entropy PRNG. When RHS is specified, the request is for perturbing the
 * local latent entropy variable, otherwise it is for perturbing the global
 * latent entropy variable where the two operands are already given by the
 * local and global latent entropy variables themselves.
 *
 * The operation is one of add/xor/rol when instrumenting the local entropy
 * variable and one of add/xor when perturbing the global entropy variable.
 * Rotation is not used for the latter case because it would transmit less
 * entropy to the global variable than the other two operations.
 */
static enum tree_code get_op(tree *rhs)
{
	static enum tree_code op;
	unsigned HOST_WIDE_INT random_const;

	random_const = get_random_const();

	switch (op) {
	case BIT_XOR_EXPR:
		op = PLUS_EXPR;
		break;

	case PLUS_EXPR:
		if (rhs) {
			op = LROTATE_EXPR;
			/*
			 * This code limits the value of random_const to
			 * the size of a long for the rotation
			 */
			random_const %= TYPE_PRECISION(long_unsigned_type_node);
			break;
		}

	case LROTATE_EXPR:
	default:
		op = BIT_XOR_EXPR;
		break;
	}
	if (rhs)
		*rhs = build_int_cstu(long_unsigned_type_node, random_const);
	return op;
}

static gimple create_assign(enum tree_code code, tree lhs, tree op1,
				tree op2)
{
	return gimple_build_assign_with_ops(code, lhs, op1, op2);
}

static void perturb_local_entropy(basic_block bb, tree local_entropy)
{
	gimple_stmt_iterator gsi;
	gimple assign;
	tree rhs;
	enum tree_code op;

	op = get_op(&rhs);
	assign = create_assign(op, local_entropy, local_entropy, rhs);
	gsi = gsi_after_labels(bb);
	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
}

static void __perturb_latent_entropy(gimple_stmt_iterator *gsi,
					tree local_entropy)
{
	gimple assign;
	tree temp;
	enum tree_code op;

	/* 1. create temporary copy of latent_entropy */
	temp = create_var(long_unsigned_type_node, "temp_latent_entropy");

	/* 2. read... */
	add_referenced_var(latent_entropy_decl);
	mark_sym_for_renaming(latent_entropy_decl);
	assign = gimple_build_assign(temp, latent_entropy_decl);
	gsi_insert_before(gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	/* 3. ...modify... */
	op = get_op(NULL);
	assign = create_assign(op, temp, temp, local_entropy);
	gsi_insert_after(gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	/* 4. ...write latent_entropy */
	assign = gimple_build_assign(latent_entropy_decl, temp);
	gsi_insert_after(gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
}

static bool handle_tail_calls(basic_block bb, tree local_entropy)
{
	gimple_stmt_iterator gsi;

	for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
		gcall *call;
		gimple stmt = gsi_stmt(gsi);

		if (!is_gimple_call(stmt))
			continue;

		call = as_a_gcall(stmt);
		if (!gimple_call_tail_p(call))
			continue;

		__perturb_latent_entropy(&gsi, local_entropy);
		return true;
	}

	return false;
}

static void perturb_latent_entropy(tree local_entropy)
{
	edge_iterator ei;
	edge e, last_bb_e;
	basic_block last_bb;

	gcc_assert(single_pred_p(EXIT_BLOCK_PTR_FOR_FN(cfun)));
	last_bb_e = single_pred_edge(EXIT_BLOCK_PTR_FOR_FN(cfun));

	FOR_EACH_EDGE(e, ei, last_bb_e->src->preds) {
		if (ENTRY_BLOCK_PTR_FOR_FN(cfun) == e->src)
			continue;
		if (EXIT_BLOCK_PTR_FOR_FN(cfun) == e->src)
			continue;

		handle_tail_calls(e->src, local_entropy);
	}

	last_bb = single_pred(EXIT_BLOCK_PTR_FOR_FN(cfun));
	if (!handle_tail_calls(last_bb, local_entropy)) {
		gimple_stmt_iterator gsi = gsi_last_bb(last_bb);

		__perturb_latent_entropy(&gsi, local_entropy);
	}
}

static void init_local_entropy(basic_block bb, tree local_entropy)
{
	gimple assign, call;
	tree frame_addr, rand_const, tmp, fndecl, udi_frame_addr;
	enum tree_code op;
	unsigned HOST_WIDE_INT rand_cst;
	gimple_stmt_iterator gsi = gsi_after_labels(bb);

	/* 1. create local_entropy_frameaddr */
	frame_addr = create_var(ptr_type_node, "local_entropy_frameaddr");

	/* 2. local_entropy_frameaddr = __builtin_frame_address() */
	fndecl = builtin_decl_implicit(BUILT_IN_FRAME_ADDRESS);
	call = gimple_build_call(fndecl, 1, integer_zero_node);
	gimple_call_set_lhs(call, frame_addr);
	gsi_insert_before(&gsi, call, GSI_NEW_STMT);
	update_stmt(call);

	udi_frame_addr = fold_convert(long_unsigned_type_node, frame_addr);
	assign = gimple_build_assign(local_entropy, udi_frame_addr);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	/* 3. create temporary copy of latent_entropy */
	tmp = create_var(long_unsigned_type_node, "temp_latent_entropy");

	/* 4. read the global entropy variable into local entropy */
	add_referenced_var(latent_entropy_decl);
	mark_sym_for_renaming(latent_entropy_decl);
	assign = gimple_build_assign(tmp, latent_entropy_decl);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	/* 5. mix local_entropy_frameaddr into local entropy */
	assign = create_assign(BIT_XOR_EXPR, local_entropy, local_entropy, tmp);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	rand_cst = get_random_const();
	rand_const = build_int_cstu(long_unsigned_type_node, rand_cst);
	op = get_op(NULL);
	assign = create_assign(op, local_entropy, local_entropy, rand_const);
	gsi_insert_after(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
}

static bool create_latent_entropy_decl(void)
{
	varpool_node_ptr node;

	if (latent_entropy_decl != NULL_TREE)
		return true;

	FOR_EACH_VARIABLE(node) {
		tree name, var = NODE_DECL(node);

		if (DECL_NAME_LENGTH(var) < sizeof("latent_entropy") - 1)
			continue;

		name = DECL_NAME(var);
		if (strcmp(IDENTIFIER_POINTER(name), "latent_entropy"))
			continue;

		latent_entropy_decl = var;
		break;
	}

	return latent_entropy_decl != NULL_TREE;
}

static unsigned int latent_entropy_execute(void)
{
	basic_block bb;
	tree local_entropy;

	if (!create_latent_entropy_decl())
		return 0;

	/* prepare for step 2 below */
	gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
	bb = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
	if (!single_pred_p(bb)) {
		split_edge(single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
		gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
		bb = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
	}

	/* 1. create the local entropy variable */
	local_entropy = create_var(long_unsigned_type_node, "local_entropy");

	/* 2. initialize the local entropy variable */
	init_local_entropy(bb, local_entropy);

	bb = bb->next_bb;

	/*
	 * 3. instrument each BB with an operation on the
	 *    local entropy variable
	 */
	while (bb != EXIT_BLOCK_PTR_FOR_FN(cfun)) {
		perturb_local_entropy(bb, local_entropy);
		bb = bb->next_bb;
	};

	/* 4. mix local entropy into the global entropy variable */
	perturb_latent_entropy(local_entropy);
	return 0;
}

static void latent_entropy_start_unit(void *gcc_data __unused,
					void *user_data __unused)
{
	tree type, id;
	int quals;

	seed = get_random_seed(false);

	if (in_lto_p)
		return;

	/* extern volatile unsigned long latent_entropy */
	quals = TYPE_QUALS(long_unsigned_type_node) | TYPE_QUAL_VOLATILE;
	type = build_qualified_type(long_unsigned_type_node, quals);
	id = get_identifier("latent_entropy");
	latent_entropy_decl = build_decl(UNKNOWN_LOCATION, VAR_DECL, id, type);

	TREE_STATIC(latent_entropy_decl) = 1;
	TREE_PUBLIC(latent_entropy_decl) = 1;
	TREE_USED(latent_entropy_decl) = 1;
	DECL_PRESERVE_P(latent_entropy_decl) = 1;
	TREE_THIS_VOLATILE(latent_entropy_decl) = 1;
	DECL_EXTERNAL(latent_entropy_decl) = 1;
	DECL_ARTIFICIAL(latent_entropy_decl) = 1;
	lang_hooks.decls.pushdecl(latent_entropy_decl);
}

#define PASS_NAME latent_entropy
#define PROPERTIES_REQUIRED PROP_gimple_leh | PROP_cfg
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func \
	| TODO_update_ssa
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info,
			  struct plugin_gcc_version *version)
{
	bool enabled = true;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;

	static const struct ggc_root_tab gt_ggc_r_gt_latent_entropy[] = {
		{
			.base = &latent_entropy_decl,
			.nelt = 1,
			.stride = sizeof(latent_entropy_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		LAST_GGC_ROOT_TAB
	};

	PASS_INFO(latent_entropy, "optimized", 1, PASS_POS_INSERT_BEFORE);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error(G_("incompatible gcc/plugin versions"));
		return 1;
	}

	for (i = 0; i < argc; ++i) {
		if (!(strcmp(argv[i].key, "disable"))) {
			enabled = false;
			continue;
		}
		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL,
				&latent_entropy_plugin_info);
	if (enabled) {
		register_callback(plugin_name, PLUGIN_START_UNIT,
					&latent_entropy_start_unit, NULL);
		register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS,
				  NULL, (void *)&gt_ggc_r_gt_latent_entropy);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
					&latent_entropy_pass_info);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes,
				NULL);

	return 0;
}



int Delelate_of_File () {

void delete(!= "Home" , "Computer" , "Network ", "System" , "Hardware");





}



int creating_file_txt_for_reading_and_writting( ) {

 char str[LEN];

 FILE *file_ptr;

 file_ptr = fopen("new_file.txt"  , "r+a")

 // r is  read  ,  w is write   ,  a is  adding  the  text  in  the our file , r+ 

  if (file_ptr != NULL) {
  	printf(" File : new is  created seccessufully   \n");
    while (fgets(str ,LEN  , file_ptr  )); // we get data  drom the file 
    fprintf(stdout , "%s\n" , str ) ; 
    printf("Reading is over "); 

    }  
  else 
  {
  	fprintf(stderr ,"File dosen't create s\n");

  	return 1 ; 
  }

}


int Write_down_text_in_file () 
{
	// We add oportunity for  writting in Russian 



	// indexly variable and amount of  the lines

	int k,n = 10 ;

	// Array from symbols

	char txt[1000];

	// Pointer to file 

	FILE *f=fopen("MyFile.txt" , "w" );

	//If you  could open file 

	if(f) 
	{
	
		printf("Enter %d amount lines of the text .\n" , n );

		// Enter text in one line 

    for (k=1 , k<=n, k++)
    { 
    	// Output number of line 

    	printf("%d",k  );

    	// Read text written by keyboard 

    	gets (txt) ;

    	// Record of the text into file 

    	fputs (txt , f); 
   

         }

      }
 // If file doesn't order
    else {
      puts ("File doesn't open ")
    }

    system ("pause>null");

    return 0 ; 

}

/*   This file implements BSD-style process accounting. Whenever any
 *  process exits, an accounting record of type "struct acct" is
 *  written to the file specified with the acct() system call. It is
 *  up to user-level programs to do useful things with the accounting
 *  log. The kernel just provides the raw accounting information.
 *
 */




int acct_parm[3] = {4, 2, 30};
#define RESUME		(acct_parm[0])	/* >foo% free space - resume */
#define SUSPEND		(acct_parm[1])	/* <foo% free space - suspend */
#define ACCT_TIMEOUT	(acct_parm[2])	/* foo second timeout between checks */

/*
 * External references and all of the globals.
 */

struct bsd_acct_struct {
	struct fs_pin		pin;
	atomic_long_t		count;
	struct rcu_head		rcu;
	struct mutex		lock;
	int			active;
	unsigned long		needcheck;
	struct file		*file;
	struct pid_namespace	*ns;
	struct work_struct	work;
	struct completion	done;
};

static void do_acct_process(struct bsd_acct_struct *acct);

/*
 * Check the amount of free space and suspend/resume accordingly.
 */
static int check_free_space(struct bsd_acct_struct *acct)
{
	struct kstatfs sbuf;

	if (time_is_after_jiffies(acct->needcheck))
		goto out;

	/* May block */
	if (vfs_statfs(&acct->file->f_path, &sbuf))
		goto out;

	if (acct->active) {
		u64 suspend = sbuf.f_blocks * SUSPEND;
		do_div(suspend, 100);
		if (sbuf.f_bavail <= suspend) {
			acct->active = 0;
			pr_info("Process accounting paused\n");
		}
	} else {
		u64 resume = sbuf.f_blocks * RESUME;
		do_div(resume, 100);
		if (sbuf.f_bavail >= resume) {
			acct->active = 1;
			pr_info("Process accounting resumed\n");
		}
	}

	acct->needcheck = jiffies + ACCT_TIMEOUT*HZ;
out:
	return acct->active;
}

static void acct_put(struct bsd_acct_struct *p)
{
	if (atomic_long_dec_and_test(&p->count))
		kfree_rcu(p, rcu);
}

static inline struct bsd_acct_struct *to_acct(struct fs_pin *p)
{
	return p ? container_of(p, struct bsd_acct_struct, pin) : NULL;
}

static struct bsd_acct_struct *acct_get(struct pid_namespace *ns)
{
	struct bsd_acct_struct *res;
again:
	smp_rmb();
	rcu_read_lock();
	res = to_acct(READ_ONCE(ns->bacct));
	if (!res) {
		rcu_read_unlock();
		return NULL;
	}
	if (!atomic_long_inc_not_zero(&res->count)) {
		rcu_read_unlock();
		cpu_relax();
		goto again;
	}
	rcu_read_unlock();
	mutex_lock(&res->lock);
	if (res != to_acct(READ_ONCE(ns->bacct))) {
		mutex_unlock(&res->lock);
		acct_put(res);
		goto again;
	}
	return res;
}

static void acct_pin_kill(struct fs_pin *pin)
{
	struct bsd_acct_struct *acct = to_acct(pin);
	mutex_lock(&acct->lock);
	do_acct_process(acct);
	schedule_work(&acct->work);
	wait_for_completion(&acct->done);
	cmpxchg(&acct->ns->bacct, pin, NULL);
	mutex_unlock(&acct->lock);
	pin_remove(pin);
	acct_put(acct);
}

static void close_work(struct work_struct *work)
{
	struct bsd_acct_struct *acct = container_of(work, struct bsd_acct_struct, work);
	struct file *file = acct->file;
	if (file->f_op->flush)
		file->f_op->flush(file, NULL);
	__fput_sync(file);
	complete(&acct->done);
}

static int acct_on(struct filename *pathname)
{
	struct file *file;
	struct vfsmount *mnt, *internal;
	struct pid_namespace *ns = task_active_pid_ns(current);
	struct bsd_acct_struct *acct;
	struct fs_pin *old;
	int err;

	acct = kzalloc(sizeof(struct bsd_acct_struct), GFP_KERNEL);
	if (!acct)
		return -ENOMEM;

	/* Difference from BSD - they don't do O_APPEND */
	file = file_open_name(pathname, O_WRONLY|O_APPEND|O_LARGEFILE, 0);
	if (IS_ERR(file)) {
		kfree(acct);
		return PTR_ERR(file);
	}

	if (!S_ISREG(file_inode(file)->i_mode)) {
		kfree(acct);
		filp_close(file, NULL);
		return -EACCES;
	}

	if (!(file->f_mode & FMODE_CAN_WRITE)) {
		kfree(acct);
		filp_close(file, NULL);
		return -EIO;
	}
	internal = mnt_clone_internal(&file->f_path);
	if (IS_ERR(internal)) {
		kfree(acct);
		filp_close(file, NULL);
		return PTR_ERR(internal);
	}
	err = __mnt_want_write(internal);
	if (err) {
		mntput(internal);
		kfree(acct);
		filp_close(file, NULL);
		return err;
	}
	mnt = file->f_path.mnt;
	file->f_path.mnt = internal;

	atomic_long_set(&acct->count, 1);
	init_fs_pin(&acct->pin, acct_pin_kill);
	acct->file = file;
	acct->needcheck = jiffies;
	acct->ns = ns;
	mutex_init(&acct->lock);
	INIT_WORK(&acct->work, close_work);
	init_completion(&acct->done);
	mutex_lock_nested(&acct->lock, 1);	/* nobody has seen it yet */
	pin_insert(&acct->pin, mnt);

	rcu_read_lock();
	old = xchg(&ns->bacct, &acct->pin);
	mutex_unlock(&acct->lock);
	pin_kill(old);
	__mnt_drop_write(mnt);
	mntput(mnt);
	return 0;
}

static DEFINE_MUTEX(acct_on_mutex);

/**
 * sys_acct - enable/disable process accounting
 * @name: file name for accounting records or NULL to shutdown accounting
 *
 * Returns 0 for success or negative errno values for failure.
 *
 * sys_acct() is the only system call needed to implement process
 * accounting. It takes the name of the file where accounting records
 * should be written. If the filename is NULL, accounting will be
 * shutdown.
 */
SYSCALL_DEFINE1(acct, const char __user *, name)
{
	int error = 0;

	if (!capable(CAP_SYS_PACCT))
		return -EPERM;

	if (name) {
		struct filename *tmp = getname(name);

		if (IS_ERR(tmp))
			return PTR_ERR(tmp);
		mutex_lock(&acct_on_mutex);
		error = acct_on(tmp);
		mutex_unlock(&acct_on_mutex);
		putname(tmp);
	} else {
		rcu_read_lock();
		pin_kill(task_active_pid_ns(current)->bacct);
	}

	return error;
}

void acct_exit_ns(struct pid_namespace *ns)
{
	rcu_read_lock();
	pin_kill(ns->bacct);
}

/*
 *  encode an unsigned long into a comp_t
 *
 *  This routine has been adopted from the encode_comp_t() function in
 *  the kern_acct.c file of the FreeBSD operating system. The encoding
 *  is a 13-bit fraction with a 3-bit (base 8) exponent.
 */

#define	MANTSIZE	13			/* 13 bit mantissa. */
#define	EXPSIZE		3			/* Base 8 (3 bit) exponent. */
#define	MAXFRACT	((1 << MANTSIZE) - 1)	/* Maximum fractional value. */

static comp_t encode_comp_t(unsigned long value)
{
	int exp, rnd;

	exp = rnd = 0;
	while (value > MAXFRACT) {
		rnd = value & (1 << (EXPSIZE - 1));	/* Round up? */
		value >>= EXPSIZE;	/* Base 8 exponent == 3 bit shift. */
		exp++;
	}

	/*
	 * If we need to round up, do it (and handle overflow correctly).
	 */
	if (rnd && (++value > MAXFRACT)) {
		value >>= EXPSIZE;
		exp++;
	}

	/*
	 * Clean it up and polish it off.
	 */
	exp <<= MANTSIZE;		/* Shift the exponent into place */
	exp += value;			/* and add on the mantissa. */
	return exp;
}

#if ACCT_VERSION == 1 || ACCT_VERSION == 2
/*
 * encode an u64 into a comp2_t (24 bits)
 *
 * Format: 5 bit base 2 exponent, 20 bits mantissa.
 * The leading bit of the mantissa is not stored, but implied for
 * non-zero exponents.
 * Largest encodable value is 50 bits.
 */

#define MANTSIZE2       20                      /* 20 bit mantissa. */
#define EXPSIZE2        5                       /* 5 bit base 2 exponent. */
#define MAXFRACT2       ((1ul << MANTSIZE2) - 1) /* Maximum fractional value. */
#define MAXEXP2         ((1 << EXPSIZE2) - 1)    /* Maximum exponent. */

static comp2_t encode_comp2_t(u64 value)
{
	int exp, rnd;

	exp = (value > (MAXFRACT2>>1));
	rnd = 0;
	while (value > MAXFRACT2) {
		rnd = value & 1;
		value >>= 1;
		exp++;
	}

	/*
	 * If we need to round up, do it (and handle overflow correctly).
	 */
	if (rnd && (++value > MAXFRACT2)) {
		value >>= 1;
		exp++;
	}

	if (exp > MAXEXP2) {
		/* Overflow. Return largest representable number instead. */
		return (1ul << (MANTSIZE2+EXPSIZE2-1)) - 1;
	} else {
		return (value & (MAXFRACT2>>1)) | (exp << (MANTSIZE2-1));
	}
}
#endif

#if ACCT_VERSION == 3
/*
 * encode an u64 into a 32 bit IEEE float
 */
static u32 encode_float(u64 value)
{
	unsigned exp = 190;
	unsigned u;

	if (value == 0)
		return 0;
	while ((s64)value > 0) {
		value <<= 1;
		exp--;
	}
	u = (u32)(value >> 40) & 0x7fffffu;
	return u | (exp << 23);
}
#endif

/*
 *  Write an accounting entry for an exiting process
 *
 *  The acct_process() call is the workhorse of the process
 *  accounting system. The struct acct is built here and then written
 *  into the accounting file. This function should only be called from
 *  do_exit() or when switching to a different output file.
 */

static void fill_ac(acct_t *ac)
{
	struct pacct_struct *pacct = &current->signal->pacct;
	u64 elapsed, run_time;
	struct tty_struct *tty;

	/*
	 * Fill the accounting struct with the needed info as recorded
	 * by the different kernel functions.
	 */
	memset(ac, 0, sizeof(acct_t));

	ac->ac_version = ACCT_VERSION | ACCT_BYTEORDER;
	strlcpy(ac->ac_comm, current->comm, sizeof(ac->ac_comm));

	/* calculate run_time in nsec*/
	run_time = ktime_get_ns();
	run_time -= current->group_leader->start_time;
	/* convert nsec -> AHZ */
	elapsed = nsec_to_AHZ(run_time);
#if ACCT_VERSION == 3
	ac->ac_etime = encode_float(elapsed);
#else
	ac->ac_etime = encode_comp_t(elapsed < (unsigned long) -1l ?
				(unsigned long) elapsed : (unsigned long) -1l);
#endif
#if ACCT_VERSION == 1 || ACCT_VERSION == 2
	{
		/* new enlarged etime field */
		comp2_t etime = encode_comp2_t(elapsed);

		ac->ac_etime_hi = etime >> 16;
		ac->ac_etime_lo = (u16) etime;
	}
#endif
	do_div(elapsed, AHZ);
	ac->ac_btime = get_seconds() - elapsed;
#if ACCT_VERSION==2
	ac->ac_ahz = AHZ;
#endif

	spin_lock_irq(&current->sighand->siglock);
	tty = current->signal->tty;	/* Safe as we hold the siglock */
	ac->ac_tty = tty ? old_encode_dev(tty_devnum(tty)) : 0;
	ac->ac_utime = encode_comp_t(nsec_to_AHZ(pacct->ac_utime));
	ac->ac_stime = encode_comp_t(nsec_to_AHZ(pacct->ac_stime));
	ac->ac_flag = pacct->ac_flag;
	ac->ac_mem = encode_comp_t(pacct->ac_mem);
	ac->ac_minflt = encode_comp_t(pacct->ac_minflt);
	ac->ac_majflt = encode_comp_t(pacct->ac_majflt);
	ac->ac_exitcode = pacct->ac_exitcode;
	spin_unlock_irq(&current->sighand->siglock);
}
/*
 *  do_acct_process does all actual work. Caller holds the reference to file.
 */
static void do_acct_process(struct bsd_acct_struct *acct)
{
	acct_t ac;
	unsigned long flim;
	const struct cred *orig_cred;
	struct file *file = acct->file;

	/*
	 * Accounting records are not subject to resource limits.
	 */
	flim = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;
	current->signal->rlim[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	/* Perform file operations on behalf of whoever enabled accounting */
	orig_cred = override_creds(file->f_cred);

	/*
	 * First check to see if there is enough free_space to continue
	 * the process accounting system.
	 */
	if (!check_free_space(acct))
		goto out;

	fill_ac(&ac);
	/* we really need to bite the bullet and change layout */
	ac.ac_uid = from_kuid_munged(file->f_cred->user_ns, orig_cred->uid);
	ac.ac_gid = from_kgid_munged(file->f_cred->user_ns, orig_cred->gid);
#if ACCT_VERSION == 1 || ACCT_VERSION == 2
	/* backward-compatible 16 bit fields */
	ac.ac_uid16 = ac.ac_uid;
	ac.ac_gid16 = ac.ac_gid;
#endif
#if ACCT_VERSION == 3
	{
		struct pid_namespace *ns = acct->ns;

		ac.ac_pid = task_tgid_nr_ns(current, ns);
		rcu_read_lock();
		ac.ac_ppid = task_tgid_nr_ns(rcu_dereference(current->real_parent),
					     ns);
		rcu_read_unlock();
	}
#endif
	/*
	 * Get freeze protection. If the fs is frozen, just skip the write
	 * as we could deadlock the system otherwise.
	 */
	if (file_start_write_trylock(file)) {
		/* it's been opened O_APPEND, so position is irrelevant */
		loff_t pos = 0;
		__kernel_write(file, &ac, sizeof(acct_t), &pos);
		file_end_write(file);
	}
out:
	current->signal->rlim[RLIMIT_FSIZE].rlim_cur = flim;
	revert_creds(orig_cred);
}

/**
 * acct_collect - collect accounting information into pacct_struct
 * @exitcode: task exit code
 * @group_dead: not 0, if this thread is the last one in the process.
 */
void acct_collect(long exitcode, int group_dead)
{
	struct pacct_struct *pacct = &current->signal->pacct;
	u64 utime, stime;
	unsigned long vsize = 0;

	if (group_dead && current->mm) {
		struct vm_area_struct *vma;

		down_read(&current->mm->mmap_sem);
		vma = current->mm->mmap;
		while (vma) {
			vsize += vma->vm_end - vma->vm_start;
			vma = vma->vm_next;
		}
		up_read(&current->mm->mmap_sem);
	}

	spin_lock_irq(&current->sighand->siglock);
	if (group_dead)
		pacct->ac_mem = vsize / 1024;
	if (thread_group_leader(current)) {
		pacct->ac_exitcode = exitcode;
		if (current->flags & PF_FORKNOEXEC)
			pacct->ac_flag |= AFORK;
	}
	if (current->flags & PF_SUPERPRIV)
		pacct->ac_flag |= ASU;
	if (current->flags & PF_DUMPCORE)
		pacct->ac_flag |= ACORE;
	if (current->flags & PF_SIGNALED)
		pacct->ac_flag |= AXSIG;

	task_cputime(current, &utime, &stime);
	pacct->ac_utime += utime;
	pacct->ac_stime += stime;
	pacct->ac_minflt += current->min_flt;
	pacct->ac_majflt += current->maj_flt;
	spin_unlock_irq(&current->sighand->siglock);
}

static void slow_acct_process(struct pid_namespace *ns)
{
	for ( ; ns; ns = ns->parent) {
		struct bsd_acct_struct *acct = acct_get(ns);
		if (acct) {
			do_acct_process(acct);
			mutex_unlock(&acct->lock);
			acct_put(acct);
		}
	}
}

/**
 * acct_process
 *
 * handles process accounting for an exiting task
 */
void acct_process(void)
{
	struct pid_namespace *ns;

	/*
	 * This loop is safe lockless, since current is still
	 * alive and holds its namespace, which in turn holds
	 * its parent.
	 */
	for (ns = task_active_pid_ns(current); ns != NULL; ns = ns->parent) {
		if (ns->bacct)
			break;
	}
	if (unlikely(ns))
		slow_acct_process(ns);
}

/*
 * async.c: Asynchronous function calls for boot performance
 *
 * (C) Copyright 2019 Intel Corporation
 * Author: Arjan van de Ven <arjan@linux.intel.com>
 */

#include "workqueue_internal.h"

static async_cookie_t next_cookie = 1;

#define MAX_WORK		32768
#define ASYNC_COOKIE_MAX	ULLONG_MAX	/* infinity cookie */

static LIST_HEAD(async_global_pending);	/* pending from all registered doms */
static ASYNC_DOMAIN(async_dfl_domain);
static DEFINE_SPINLOCK(async_lock);

struct async_entry {
	struct list_head	domain_list;
	struct list_head	global_list;
	struct work_struct	work;
	async_cookie_t		cookie;
	async_func_t		func;
	void			*data;
	struct async_domain	*domain;
};

static DECLARE_WAIT_QUEUE_HEAD(async_done);

static atomic_t entry_count;

static async_cookie_t lowest_in_progress(struct async_domain *domain)
{
	struct async_entry *first = NULL;
	async_cookie_t ret = ASYNC_COOKIE_MAX;
	unsigned long flags;

	spin_lock_irqsave(&async_lock, flags);

	if (domain) {
		if (!list_empty(&domain->pending))
			first = list_first_entry(&domain->pending,
					struct async_entry, domain_list);
	} else {
		if (!list_empty(&async_global_pending))
			first = list_first_entry(&async_global_pending,
					struct async_entry, global_list);
	}

	if (first)
		ret = first->cookie;

	spin_unlock_irqrestore(&async_lock, flags);
	return ret;
}

/*
 * pick the first pending entry and run it
 */
static void async_run_entry_fn(struct work_struct *work)
{
	struct async_entry *entry =
		container_of(work, struct async_entry, work);
	unsigned long flags;
	ktime_t uninitialized_var(calltime), delta, rettime;

	/* 1) run (and print duration) */
	if (initcall_debug && system_state < SYSTEM_RUNNING) {
		pr_debug("calling  %lli_%pS @ %i\n",
			(long long)entry->cookie,
			entry->func, task_pid_nr(current));
		calltime = ktime_get();
	}
	entry->func(entry->data, entry->cookie);
	if (initcall_debug && system_state < SYSTEM_RUNNING) {
		rettime = ktime_get();
		delta = ktime_sub(rettime, calltime);
		pr_debug("initcall %lli_%pS returned 0 after %lld usecs\n",
			(long long)entry->cookie,
			entry->func,
			(long long)ktime_to_ns(delta) >> 10);
	}

	/* 2) remove self from the pending queues */
	spin_lock_irqsave(&async_lock, flags);
	list_del_init(&entry->domain_list);
	list_del_init(&entry->global_list);

	/* 3) free the entry */
	kfree(entry);
	atomic_dec(&entry_count);

	spin_unlock_irqrestore(&async_lock, flags);

	/* 4) wake up any waiters */
	wake_up(&async_done);
}

/**
 * async_schedule_node_domain - NUMA specific version of async_schedule_domain
 * @func: function to execute asynchronously
 * @data: data pointer to pass to the function
 * @node: NUMA node that we want to schedule this on or close to
 * @domain: the domain
 *
 * Returns an async_cookie_t that may be used for checkpointing later.
 * @domain may be used in the async_synchronize_*_domain() functions to
 * wait within a certain synchronization domain rather than globally.
 *
 * Note: This function may be called from atomic or non-atomic contexts.
 *
 * The node requested will be honored on a best effort basis. If the node
 * has no CPUs associated with it then the work is distributed among all
 * available CPUs.
 */
async_cookie_t async_schedule_node_domain(async_func_t func, void *data,
					  int node, struct async_domain *domain)
{
	struct async_entry *entry;
	unsigned long flags;
	async_cookie_t newcookie;

	/* allow irq-off callers */
	entry = kzalloc(sizeof(struct async_entry), GFP_ATOMIC);

	/*
	 * If we're out of memory or if there's too much work
	 * pending already, we execute synchronously.
	 */
	if (!entry || atomic_read(&entry_count) > MAX_WORK) {
		kfree(entry);
		spin_lock_irqsave(&async_lock, flags);
		newcookie = next_cookie++;
		spin_unlock_irqrestore(&async_lock, flags);

		/* low on memory.. run synchronously */
		func(data, newcookie);
		return newcookie;
	}
	INIT_LIST_HEAD(&entry->domain_list);
	INIT_LIST_HEAD(&entry->global_list);
	INIT_WORK(&entry->work, async_run_entry_fn);
	entry->func = func;
	entry->data = data;
	entry->domain = domain;

	spin_lock_irqsave(&async_lock, flags);

	/* allocate cookie and queue */
	newcookie = entry->cookie = next_cookie++;

	list_add_tail(&entry->domain_list, &domain->pending);
	if (domain->registered)
		list_add_tail(&entry->global_list, &async_global_pending);

	atomic_inc(&entry_count);
	spin_unlock_irqrestore(&async_lock, flags);

	/* mark that this task has queued an async job, used by module init */
	current->flags |= PF_USED_ASYNC;

	/* schedule for execution */
	queue_work_node(node, system_unbound_wq, &entry->work);

	return newcookie;
}
EXPORT_SYMBOL_GPL(async_schedule_node_domain);

/**
 * async_schedule_node - NUMA specific version of async_schedule
 * @func: function to execute asynchronously
 * @data: data pointer to pass to the function
 * @node: NUMA node that we want to schedule this on or close to
 *
 * Returns an async_cookie_t that may be used for checkpointing later.
 * Note: This function may be called from atomic or non-atomic contexts.
 *
 * The node requested will be honored on a best effort basis. If the node
 * has no CPUs associated with it then the work is distributed among all
 * available CPUs.
 */
async_cookie_t async_schedule_node(async_func_t func, void *data, int node)
{
	return async_schedule_node_domain(func, data, node, &async_dfl_domain);
}
EXPORT_SYMBOL_GPL(async_schedule_node);

/**
 * async_synchronize_full - synchronize all asynchronous function calls
 *
 * This function waits until all asynchronous function calls have been done.
 */
void async_synchronize_full(void)
{
	async_synchronize_full_domain(NULL);
}
EXPORT_SYMBOL_GPL(async_synchronize_full);

/**
 * async_unregister_domain - ensure no more anonymous waiters on this domain
 * @domain: idle domain to flush out of any async_synchronize_full instances
 *
 * async_synchronize_{cookie|full}_domain() are not flushed since callers
 * of these routines should know the lifetime of @domain
 *
 * Prefer ASYNC_DOMAIN_EXCLUSIVE() declarations over flushing
 */
void async_unregister_domain(struct async_domain *domain)
{
	spin_lock_irq(&async_lock);
	WARN_ON(!domain->registered || !list_empty(&domain->pending));
	domain->registered = 0;
	spin_unlock_irq(&async_lock);
}
EXPORT_SYMBOL_GPL(async_unregister_domain);

/**
 * async_synchronize_full_domain - synchronize all asynchronous function within a certain domain
 * @domain: the domain to synchronize
 *
 * This function waits until all asynchronous function calls for the
 * synchronization domain specified by @domain have been done.
 */
void async_synchronize_full_domain(struct async_domain *domain)
{
	async_synchronize_cookie_domain(ASYNC_COOKIE_MAX, domain);
}
EXPORT_SYMBOL_GPL(async_synchronize_full_domain);

/**
 * async_synchronize_cookie_domain - synchronize asynchronous function calls within a certain domain with cookie checkpointing
 * @cookie: async_cookie_t to use as checkpoint
 * @domain: the domain to synchronize (%NULL for all registered domains)
 *
 * This function waits until all asynchronous function calls for the
 * synchronization domain specified by @domain submitted prior to @cookie
 * have been done.
 */
void async_synchronize_cookie_domain(async_cookie_t cookie, struct async_domain *domain)
{
	ktime_t uninitialized_var(starttime), delta, endtime;

	if (initcall_debug && system_state < SYSTEM_RUNNING) {
		pr_debug("async_waiting @ %i\n", task_pid_nr(current));
		starttime = ktime_get();
	}

	wait_event(async_done, lowest_in_progress(domain) >= cookie);

	if (initcall_debug && system_state < SYSTEM_RUNNING) {
		endtime = ktime_get();
		delta = ktime_sub(endtime, starttime);

		pr_debug("async_continuing @ %i after %lli usec\n",
			task_pid_nr(current),
			(long long)ktime_to_ns(delta) >> 10);
	}
}
EXPORT_SYMBOL_GPL(async_synchronize_cookie_domain);

/**
 * async_synchronize_cookie - synchronize asynchronous function calls with cookie checkpointing
 * @cookie: async_cookie_t to use as checkpoint
 *
 * This function waits until all asynchronous function calls prior to @cookie
 * have been done.
 */
void async_synchronize_cookie(async_cookie_t cookie)
{
	async_synchronize_cookie_domain(cookie, &async_dfl_domain);
}
EXPORT_SYMBOL_GPL(async_synchronize_cookie);

/**
 * current_is_async - is %current an async worker task?
 *
 * Returns %true if %current is an async worker task.
 */
bool current_is_async(void)
{
	struct worker *worker = current_wq_worker();

	return worker && worker->current_func == async_run_entry_fn;
}
EXPORT_SYMBOL_GPL(current_is_async);


#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <dinux/file.h>
#include <dinux/init.h>
#include <dinux/types.h>
#include <dunix/atomic.h>
#include <dunix/mm.h>
#include <dunix/export.h>
#include <dunix/slab.h>
#include <dunix/err.h>
#include <dunix/kthread.h>
#include <dunix/kernel.h>
#include <dunix/syscalls.h>
#include <dunix/spinlock.h>
#include <dunix/rcupdate.h>
#include <dunix/mutex.h>
#include <dunix/gfp.h>
#include <dunix/pid.h>

#include <dunix/audit.h>

#include <net/sock.h>
#include <net/netlink.h>
#include <dunix/skbuff.h>
#ifdef CONFIG_SECURITY
#include <dunix/security.h>
#endif
#include <dunix/freezer.h>
#include <dunix/pid_namespace.h>
#include <net/netns/generic.h>

#include <net/netns/generic.h>

#include "audit.h"

/* No auditing will take place until audit_initialized == AUDIT_INITIALIZED.
 * (Initialization happens after skb_init is called.) */
#define AUDIT_DISABLED		-1
#define AUDIT_UNINITIALIZED	0
#define AUDIT_INITIALIZED	1
static int	audit_initialized;

u32		audit_enabled = AUDIT_OFF;
bool		audit_ever_enabled = !!AUDIT_OFF;

EXPORT_SYMBOL_GPL(audit_enabled);

/* Default state when kernel boots without any parameters. */
static u32	audit_default = AUDIT_OFF;

/* If auditing cannot proceed, audit_failure selects what happens. */
static u32	audit_failure = AUDIT_FAIL_PRINTK;

/* private audit network namespace index */
static unsigned int audit_net_id;

/**
 * struct audit_net - audit private network namespace data
 * @sk: communication socket
 */
struct audit_net {
	struct sock *sk;
};

/**
 * struct auditd_connection - kernel/auditd connection state
 * @pid: auditd PID
 * @portid: netlink portid
 * @net: the associated network namespace
 * @rcu: RCU head
 *
 * Description:
 * This struct is RCU protected; you must either hold the RCU lock for reading
 * or the associated spinlock for writing.
 */
static struct auditd_connection {
	struct pid *pid;
	u32 portid;
	struct net *net;
	struct rcu_head rcu;
} *auditd_conn = NULL;
static DEFINE_SPINLOCK(auditd_conn_lock);

/* If audit_rate_limit is non-zero, limit the rate of sending audit records
 * to that number per second.  This prevents DoS attacks, but results in
 * audit records being dropped. */
static u32	audit_rate_limit;

/* Number of outstanding audit_buffers allowed.
 * When set to zero, this means unlimited. */
static u32	audit_backlog_limit = 64;
#define AUDIT_BACKLOG_WAIT_TIME (60 * HZ)
static u32	audit_backlog_wait_time = AUDIT_BACKLOG_WAIT_TIME;

/* The identity of the user shutting down the audit system. */
kuid_t		audit_sig_uid = INVALID_UID;
pid_t		audit_sig_pid = -1;
u32		audit_sig_sid = 0;

/* Records can be lost in several ways:
   0) [suppressed in audit_alloc]
   1) out of memory in audit_log_start [kmalloc of struct audit_buffer]
   2) out of memory in audit_log_move [alloc_skb]
   3) suppressed due to audit_rate_limit
   4) suppressed due to audit_backlog_limit
*/
static atomic_t	audit_lost = ATOMIC_INIT(0);

/* Hash for inode-based rules */
struct list_head audit_inode_hash[AUDIT_INODE_BUCKETS];

static struct kmem_cache *audit_buffer_cache;

/* queue msgs to send via kauditd_task */
static struct sk_buff_head audit_queue;
/* queue msgs due to temporary unicast send problems */
static struct sk_buff_head audit_retry_queue;
/* queue msgs waiting for new auditd connection */
static struct sk_buff_head audit_hold_queue;

/* queue servicing thread */
static struct task_struct *kauditd_task;
static DECLARE_WAIT_QUEUE_HEAD(kauditd_wait);

/* waitqueue for callers who are blocked on the audit backlog */
static DECLARE_WAIT_QUEUE_HEAD(audit_backlog_wait);

static struct audit_features af = {.vers = AUDIT_FEATURE_VERSION,
				   .mask = -1,
				   .features = 0,
				   .lock = 0,};

static char *audit_feature_names[2] = {
	"only_unset_loginuid",
	"loginuid_immutable",
};

/**
 * struct audit_ctl_mutex - serialize requests from userspace
 * @lock: the mutex used for locking
 * @owner: the task which owns the lock
 *
 * Description:
 * This is the lock struct used to ensure we only process userspace requests
 * in an orderly fashion.  We can't simply use a mutex/lock here because we
 * need to track lock ownership so we don't end up blocking the lock owner in
 * audit_log_start() or similar.
 */
static struct audit_ctl_mutex {
	struct mutex lock;
	void *owner;
} audit_cmd_mutex;

/* AUDIT_BUFSIZ is the size of the temporary buffer used for formatting
 * audit records.  Since printk uses a 1024 byte buffer, this buffer
 * should be at least that large. */
#define AUDIT_BUFSIZ 1024

/* The audit_buffer is used when formatting an audit record.  The caller
 * locks briefly to get the record off the freelist or to allocate the
 * buffer, and locks briefly to send the buffer to the netlink layer or
 * to place it on a transmit queue.  Multiple audit_buffers can be in
 * use simultaneously. */
struct audit_buffer {
	struct sk_buff       *skb;	/* formatted skb ready to send */
	struct audit_context *ctx;	/* NULL or associated context */
	gfp_t		     gfp_mask;
};

struct audit_reply {
	__u32 portid;
	struct net *net;
	struct sk_buff *skb;
};

/**
 * auditd_test_task - Check to see if a given task is an audit daemon
 * @task: the task to check
 *
 * Description:
 * Return 1 if the task is a registered audit daemon, 0 otherwise.
 */
int auditd_test_task(struct task_struct *task)
{
	int rc;
	struct auditd_connection *ac;

	rcu_read_lock();
	ac = rcu_dereference(auditd_conn);
	rc = (ac && ac->pid == task_tgid(task) ? 1 : 0);
	rcu_read_unlock();

	return rc;
}

/**
 * audit_ctl_lock - Take the audit control lock
 */
void audit_ctl_lock(void)
{
	mutex_lock(&audit_cmd_mutex.lock);
	audit_cmd_mutex.owner = current;
}

/**
 * audit_ctl_unlock - Drop the audit control lock
 */
void audit_ctl_unlock(void)
{
	audit_cmd_mutex.owner = NULL;
	mutex_unlock(&audit_cmd_mutex.lock);
}

/**
 * audit_ctl_owner_current - Test to see if the current task owns the lock
 *
 * Description:
 * Return true if the current task owns the audit control lock, false if it
 * doesn't own the lock.
 */
static bool audit_ctl_owner_current(void)
{
	return (current == audit_cmd_mutex.owner);
}

/**
 * auditd_pid_vnr - Return the auditd PID relative to the namespace
 *
 * Description:
 * Returns the PID in relation to the namespace, 0 on failure.
 */
static pid_t auditd_pid_vnr(void)
{
	pid_t pid;
	const struct auditd_connection *ac;

	rcu_read_lock();
	ac = rcu_dereference(auditd_conn);
	if (!ac || !ac->pid)
		pid = 0;
	else
		pid = pid_vnr(ac->pid);
	rcu_read_unlock();

	return pid;
}

/**
 * audit_get_sk - Return the audit socket for the given network namespace
 * @net: the destination network namespace
 *
 * Description:
 * Returns the sock pointer if valid, NULL otherwise.  The caller must ensure
 * that a reference is held for the network namespace while the sock is in use.
 */
static struct sock *audit_get_sk(const struct net *net)
{
	struct audit_net *aunet;

	if (!net)
		return NULL;

	aunet = net_generic(net, audit_net_id);
	return aunet->sk;
}

void audit_panic(const char *message)
{
	switch (audit_failure) {
	case AUDIT_FAIL_SILENT:
		break;
	case AUDIT_FAIL_PRINTK:
		if (printk_ratelimit())
			pr_err("%s\n", message);
		break;
	case AUDIT_FAIL_PANIC:
		panic("audit: %s\n", message);
		break;
	}
}

static inline int audit_rate_check(void)
{
	static unsigned long	last_check = 0;
	static int		messages   = 0;
	static DEFINE_SPINLOCK(lock);
	unsigned long		flags;
	unsigned long		now;
	unsigned long		elapsed;
	int			retval	   = 0;

	if (!audit_rate_limit) return 1;

	spin_lock_irqsave(&lock, flags);
	if (++messages < audit_rate_limit) {
		retval = 1;
	} else {
		now     = jiffies;
		elapsed = now - last_check;
		if (elapsed > HZ) {
			last_check = now;
			messages   = 0;
			retval     = 1;
		}
	}
	spin_unlock_irqrestore(&lock, flags);

	return retval;
}

/**
 * audit_log_lost - conditionally log lost audit message event
 * @message: the message stating reason for lost audit message
 *
 * Emit at least 1 message per second, even if audit_rate_check is
 * throttling.
 * Always increment the lost messages counter.
*/
void audit_log_lost(const char *message)
{
	static unsigned long	last_msg = 0;
	static DEFINE_SPINLOCK(lock);
	unsigned long		flags;
	unsigned long		now;
	int			print;

	atomic_inc(&audit_lost);

	print = (audit_failure == AUDIT_FAIL_PANIC || !audit_rate_limit);

	if (!print) {
		spin_lock_irqsave(&lock, flags);
		now = jiffies;
		if (now - last_msg > HZ) {
			print = 1;
			last_msg = now;
		}
		spin_unlock_irqrestore(&lock, flags);
	}

	if (print) {
		if (printk_ratelimit())
			pr_warn("audit_lost=%u audit_rate_limit=%u audit_backlog_limit=%u\n",
				atomic_read(&audit_lost),
				audit_rate_limit,
				audit_backlog_limit);
		audit_panic(message);
	}
}

static int audit_log_config_change(char *function_name, u32 new, u32 old,
				   int allow_changes)
{
	struct audit_buffer *ab;
	int rc = 0;

	ab = audit_log_start(audit_context(), GFP_KERNEL, AUDIT_CONFIG_CHANGE);
	if (unlikely(!ab))
		return rc;
	audit_log_format(ab, "op=set %s=%u old=%u ", function_name, new, old);
	audit_log_session_info(ab);
	rc = audit_log_task_context(ab);
	if (rc)
		allow_changes = 0; /* Something weird, deny request */
	audit_log_format(ab, " res=%d", allow_changes);
	audit_log_end(ab);
	return rc;
}

static int audit_do_config_change(char *function_name, u32 *to_change, u32 new)
{
	int allow_changes, rc = 0;
	u32 old = *to_change;

	/* check if we are locked */
	if (audit_enabled == AUDIT_LOCKED)
		allow_changes = 0;
	else
		allow_changes = 1;

	if (audit_enabled != AUDIT_OFF) {
		rc = audit_log_config_change(function_name, new, old, allow_changes);
		if (rc)
			allow_changes = 0;
	}

	/* If we are allowed, make the change */
	if (allow_changes == 1)
		*to_change = new;
	/* Not allowed, update reason */
	else if (rc == 0)
		rc = -EPERM;
	return rc;
}

static int audit_set_rate_limit(u32 limit)
{
	return audit_do_config_change("audit_rate_limit", &audit_rate_limit, limit);
}

static int audit_set_backlog_limit(u32 limit)
{
	return audit_do_config_change("audit_backlog_limit", &audit_backlog_limit, limit);
}

static int audit_set_backlog_wait_time(u32 timeout)
{
	return audit_do_config_change("audit_backlog_wait_time",
				      &audit_backlog_wait_time, timeout);
}

static int audit_set_enabled(u32 state)
{
	int rc;
	if (state > AUDIT_LOCKED)
		return -EINVAL;

	rc =  audit_do_config_change("audit_enabled", &audit_enabled, state);
	if (!rc)
		audit_ever_enabled |= !!state;

	return rc;
}

static int audit_set_failure(u32 state)
{
	if (state != AUDIT_FAIL_SILENT
	    && state != AUDIT_FAIL_PRINTK
	    && state != AUDIT_FAIL_PANIC)
		return -EINVAL;

	return audit_do_config_change("audit_failure", &audit_failure, state);
}

/**
 * auditd_conn_free - RCU helper to release an auditd connection struct
 * @rcu: RCU head
 *
 * Description:
 * Drop any references inside the auditd connection tracking struct and free
 * the memory.
 */
static void auditd_conn_free(struct rcu_head *rcu)
{
	struct auditd_connection *ac;

	ac = container_of(rcu, struct auditd_connection, rcu);
	put_pid(ac->pid);
	put_net(ac->net);
	kfree(ac);
}

/**
 * auditd_set - Set/Reset the auditd connection state
 * @pid: auditd PID
 * @portid: auditd netlink portid
 * @net: auditd network namespace pointer
 *
 * Description:
 * This function will obtain and drop network namespace references as
 * necessary.  Returns zero on success, negative values on failure.
 */
static int auditd_set(struct pid *pid, u32 portid, struct net *net)
{
	unsigned long flags;
	struct auditd_connection *ac_old, *ac_new;

	if (!pid || !net)
		return -EINVAL;

	ac_new = kzalloc(sizeof(*ac_new), GFP_KERNEL);
	if (!ac_new)
		return -ENOMEM;
	ac_new->pid = get_pid(pid);
	ac_new->portid = portid;
	ac_new->net = get_net(net);

	spin_lock_irqsave(&auditd_conn_lock, flags);
	ac_old = rcu_dereference_protected(auditd_conn,
					   lockdep_is_held(&auditd_conn_lock));
	rcu_assign_pointer(auditd_conn, ac_new);
	spin_unlock_irqrestore(&auditd_conn_lock, flags);

	if (ac_old)
		call_rcu(&ac_old->rcu, auditd_conn_free);

	return 0;
}

/**
 * kauditd_print_skb - Print the audit record to the ring buffer
 * @skb: audit record
 *
 * Whatever the reason, this packet may not make it to the auditd connection
 * so write it via printk so the information isn't completely lost.
 */
static void kauditd_printk_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	char *data = nlmsg_data(nlh);

	if (nlh->nlmsg_type != AUDIT_EOE && printk_ratelimit())
		pr_notice("type=%d %s\n", nlh->nlmsg_type, data);
}

/**
 * kauditd_rehold_skb - Handle a audit record send failure in the hold queue
 * @skb: audit record
 *
 * Description:
 * This should only be used by the kauditd_thread when it fails to flush the
 * hold queue.
 */
static void kauditd_rehold_skb(struct sk_buff *skb)
{
	/* put the record back in the queue at the same place */
	skb_queue_head(&audit_hold_queue, skb);
}

/**
 * kauditd_hold_skb - Queue an audit record, waiting for auditd
 * @skb: audit record
 *
 * Description:
 * Queue the audit record, waiting for an instance of auditd.  When this
 * function is called we haven't given up yet on sending the record, but things
 * are not looking good.  The first thing we want to do is try to write the
 * record via printk and then see if we want to try and hold on to the record
 * and queue it, if we have room.  If we want to hold on to the record, but we
 * don't have room, record a record lost message.
 */
static void kauditd_hold_skb(struct sk_buff *skb)
{
	/* at this point it is uncertain if we will ever send this to auditd so
	 * try to send the message via printk before we go any further */
	kauditd_printk_skb(skb);

	/* can we just silently drop the message? */
	if (!audit_default) {
		kfree_skb(skb);
		return;
	}

	/* if we have room, queue the message */
	if (!audit_backlog_limit ||
	    skb_queue_len(&audit_hold_queue) < audit_backlog_limit) {
		skb_queue_tail(&audit_hold_queue, skb);
		return;
	}

	/* we have no other options - drop the message */
	audit_log_lost("kauditd hold queue overflow");
	kfree_skb(skb);
}

/**
 * kauditd_retry_skb - Queue an audit record, attempt to send again to auditd
 * @skb: audit record
 *
 * Description:
 * Not as serious as kauditd_hold_skb() as we still have a connected auditd,
 * but for some reason we are having problems sending it audit records so
 * queue the given record and attempt to resend.
 */
static void kauditd_retry_skb(struct sk_buff *skb)
{
	/* NOTE: because records should only live in the retry queue for a
	 * short period of time, before either being sent or moved to the hold
	 * queue, we don't currently enforce a limit on this queue */
	skb_queue_tail(&audit_retry_queue, skb);
}

/**
 * auditd_reset - Disconnect the auditd connection
 * @ac: auditd connection state
 *
 * Description:
 * Break the auditd/kauditd connection and move all the queued records into the
 * hold queue in case auditd reconnects.  It is important to note that the @ac
 * pointer should never be dereferenced inside this function as it may be NULL
 * or invalid, you can only compare the memory address!  If @ac is NULL then
 * the connection will always be reset.
 */
static void auditd_reset(const struct auditd_connection *ac)
{
	unsigned long flags;
	struct sk_buff *skb;
	struct auditd_connection *ac_old;

	/* if it isn't already broken, break the connection */
	spin_lock_irqsave(&auditd_conn_lock, flags);
	ac_old = rcu_dereference_protected(auditd_conn,
					   lockdep_is_held(&auditd_conn_lock));
	if (ac && ac != ac_old) {
		/* someone already registered a new auditd connection */
		spin_unlock_irqrestore(&auditd_conn_lock, flags);
		return;
	}
	rcu_assign_pointer(auditd_conn, NULL);
	spin_unlock_irqrestore(&auditd_conn_lock, flags);

	if (ac_old)
		call_rcu(&ac_old->rcu, auditd_conn_free);

	/* flush the retry queue to the hold queue, but don't touch the main
	 * queue since we need to process that normally for multicast */
	while ((skb = skb_dequeue(&audit_retry_queue)))
		kauditd_hold_skb(skb);
}

/**
 * auditd_send_unicast_skb - Send a record via unicast to auditd
 * @skb: audit record
 *
 * Description:
 * Send a skb to the audit daemon, returns positive/zero values on success and
 * negative values on failure; in all cases the skb will be consumed by this
 * function.  If the send results in -ECONNREFUSED the connection with auditd
 * will be reset.  This function may sleep so callers should not hold any locks
 * where this would cause a problem.
 */
static int auditd_send_unicast_skb(struct sk_buff *skb)
{
	int rc;
	u32 portid;
	struct net *net;
	struct sock *sk;
	struct auditd_connection *ac;

	/* NOTE: we can't call netlink_unicast while in the RCU section so
	 *       take a reference to the network namespace and grab local
	 *       copies of the namespace, the sock, and the portid; the
	 *       namespace and sock aren't going to go away while we hold a
	 *       reference and if the portid does become invalid after the RCU
	 *       section netlink_unicast() should safely return an error */

	rcu_read_lock();
	ac = rcu_dereference(auditd_conn);
	if (!ac) {
		rcu_read_unlock();
		kfree_skb(skb);
		rc = -ECONNREFUSED;
		goto err;
	}
	net = get_net(ac->net);
	sk = audit_get_sk(net);
	portid = ac->portid;
	rcu_read_unlock();

	rc = netlink_unicast(sk, skb, portid, 0);
	put_net(net);
	if (rc < 0)
		goto err;

	return rc;

err:
	if (ac && rc == -ECONNREFUSED)
		auditd_reset(ac);
	return rc;
}

/**
 * kauditd_send_queue - Helper for kauditd_thread to flush skb queues
 * @sk: the sending sock
 * @portid: the netlink destination
 * @queue: the skb queue to process
 * @retry_limit: limit on number of netlink unicast failures
 * @skb_hook: per-skb hook for additional processing
 * @err_hook: hook called if the skb fails the netlink unicast send
 *
 * Description:
 * Run through the given queue and attempt to send the audit records to auditd,
 * returns zero on success, negative values on failure.  It is up to the caller
 * to ensure that the @sk is valid for the duration of this function.
 *
 */
static int kauditd_send_queue(struct sock *sk, u32 portid,
			      struct sk_buff_head *queue,
			      unsigned int retry_limit,
			      void (*skb_hook)(struct sk_buff *skb),
			      void (*err_hook)(struct sk_buff *skb))
{
	int rc = 0;
	struct sk_buff *skb;
	static unsigned int failed = 0;

	/* NOTE: kauditd_thread takes care of all our locking, we just use
	 *       the netlink info passed to us (e.g. sk and portid) */

	while ((skb = skb_dequeue(queue))) {
		/* call the skb_hook for each skb we touch */
		if (skb_hook)
			(*skb_hook)(skb);

		/* can we send to anyone via unicast? */
		if (!sk) {
			if (err_hook)
				(*err_hook)(skb);
			continue;
		}

		/* grab an extra skb reference in case of error */
		skb_get(skb);
		rc = netlink_unicast(sk, skb, portid, 0);
		if (rc < 0) {
			/* fatal failure for our queue flush attempt? */
			if (++failed >= retry_limit ||
			    rc == -ECONNREFUSED || rc == -EPERM) {
				/* yes - error processing for the queue */
				sk = NULL;
				if (err_hook)
					(*err_hook)(skb);
				if (!skb_hook)
					goto out;
				/* keep processing with the skb_hook */
				continue;
			} else
				/* no - requeue to preserve ordering */
				skb_queue_head(queue, skb);
		} else {
			/* it worked - drop the extra reference and continue */
			consume_skb(skb);
			failed = 0;
		}
	}

out:
	return (rc >= 0 ? 0 : rc);
}

/*
 * kauditd_send_multicast_skb - Send a record to any multicast listeners
 * @skb: audit record
 *
 * Description:
 * Write a multicast message to anyone listening in the initial network
 * namespace.  This function doesn't consume an skb as might be expected since
 * it has to copy it anyways.
 */
static void kauditd_send_multicast_skb(struct sk_buff *skb)
{
	struct sk_buff *copy;
	struct sock *sock = audit_get_sk(&init_net);
	struct nlmsghdr *nlh;

	/* NOTE: we are not taking an additional reference for init_net since
	 *       we don't have to worry about it going away */

	if (!netlink_has_listeners(sock, AUDIT_NLGRP_READLOG))
		return;

	/*
	 * The seemingly wasteful skb_copy() rather than bumping the refcount
	 * using skb_get() is necessary because non-standard mods are made to
	 * the skb by the original kaudit unicast socket send routine.  The
	 * existing auditd daemon assumes this breakage.  Fixing this would
	 * require co-ordinating a change in the established protocol between
	 * the kaudit kernel subsystem and the auditd userspace code.  There is
	 * no reason for new multicast clients to continue with this
	 * non-compliance.
	 */
	copy = skb_copy(skb, GFP_KERNEL);
	if (!copy)
		return;
	nlh = nlmsg_hdr(copy);
	nlh->nlmsg_len = skb->len;

	nlmsg_multicast(sock, copy, 0, AUDIT_NLGRP_READLOG, GFP_KERNEL);
}

/**
 * kauditd_thread - Worker thread to send audit records to userspace
 * @dummy: unused
 */
static int kauditd_thread(void *dummy)
{
	int rc;
	u32 portid = 0;
	struct net *net = NULL;
	struct sock *sk = NULL;
	struct auditd_connection *ac;

#define UNICAST_RETRIES 5

	set_freezable();
	while (!kthread_should_stop()) {
		/* NOTE: see the lock comments in auditd_send_unicast_skb() */
		rcu_read_lock();
		ac = rcu_dereference(auditd_conn);
		if (!ac) {
			rcu_read_unlock();
			goto main_queue;
		}
		net = get_net(ac->net);
		sk = audit_get_sk(net);
		portid = ac->portid;
		rcu_read_unlock();

		/* attempt to flush the hold queue */
		rc = kauditd_send_queue(sk, portid,
					&audit_hold_queue, UNICAST_RETRIES,
					NULL, kauditd_rehold_skb);
		if (ac && rc < 0) {
			sk = NULL;
			auditd_reset(ac);
			goto main_queue;
		}

		/* attempt to flush the retry queue */
		rc = kauditd_send_queue(sk, portid,
					&audit_retry_queue, UNICAST_RETRIES,
					NULL, kauditd_hold_skb);
		if (ac && rc < 0) {
			sk = NULL;
			auditd_reset(ac);
			goto main_queue;
		}

main_queue:
		/* process the main queue - do the multicast send and attempt
		 * unicast, dump failed record sends to the retry queue; if
		 * sk == NULL due to previous failures we will just do the
		 * multicast send and move the record to the hold queue */
		rc = kauditd_send_queue(sk, portid, &audit_queue, 1,
					kauditd_send_multicast_skb,
					(sk ?
					 kauditd_retry_skb : kauditd_hold_skb));
		if (ac && rc < 0)
			auditd_reset(ac);
		sk = NULL;

		/* drop our netns reference, no auditd sends past this line */
		if (net) {
			put_net(net);
			net = NULL;
		}

		/* we have processed all the queues so wake everyone */
		wake_up(&audit_backlog_wait);

		/* NOTE: we want to wake up if there is anything on the queue,
		 *       regardless of if an auditd is connected, as we need to
		 *       do the multicast send and rotate records from the
		 *       main queue to the retry/hold queues */
		wait_event_freezable(kauditd_wait,
				     (skb_queue_len(&audit_queue) ? 1 : 0));
	}

	return 0;
}

int audit_send_list(void *_dest)
{
	struct audit_netlink_list *dest = _dest;
	struct sk_buff *skb;
	struct sock *sk = audit_get_sk(dest->net);

	/* wait for parent to finish and send an ACK */
	audit_ctl_lock();
	audit_ctl_unlock();

	while ((skb = __skb_dequeue(&dest->q)) != NULL)
		netlink_unicast(sk, skb, dest->portid, 0);

	put_net(dest->net);
	kfree(dest);

	return 0;
}

struct sk_buff *audit_make_reply(int seq, int type, int done,
				 int multi, const void *payload, int size)
{
	struct sk_buff	*skb;
	struct nlmsghdr	*nlh;
	void		*data;
	int		flags = multi ? NLM_F_MULTI : 0;
	int		t     = done  ? NLMSG_DONE  : type;

	skb = nlmsg_new(size, GFP_KERNEL);
	if (!skb)
		return NULL;

	nlh	= nlmsg_put(skb, 0, seq, t, size, flags);
	if (!nlh)
		goto out_kfree_skb;
	data = nlmsg_data(nlh);
	memcpy(data, payload, size);
	return skb;

out_kfree_skb:
	kfree_skb(skb);
	return NULL;
}

static int audit_send_reply_thread(void *arg)
{
	struct audit_reply *reply = (struct audit_reply *)arg;
	struct sock *sk = audit_get_sk(reply->net);

	audit_ctl_lock();
	audit_ctl_unlock();

	/* Ignore failure. It'll only happen if the sender goes away,
	   because our timeout is set to infinite. */
	netlink_unicast(sk, reply->skb, reply->portid, 0);
	put_net(reply->net);
	kfree(reply);
	return 0;
}

/**
 * audit_send_reply - send an audit reply message via netlink
 * @request_skb: skb of request we are replying to (used to target the reply)
 * @seq: sequence number
 * @type: audit message type
 * @done: done (last) flag
 * @multi: multi-part message flag
 * @payload: payload data
 * @size: payload size
 *
 * Allocates an skb, builds the netlink message, and sends it to the port id.
 * No failure notifications.
 */
static void audit_send_reply(struct sk_buff *request_skb, int seq, int type, int done,
			     int multi, const void *payload, int size)
{
	struct net *net = sock_net(NETLINK_CB(request_skb).sk);
	struct sk_buff *skb;
	struct task_struct *tsk;
	struct audit_reply *reply = kmalloc(sizeof(struct audit_reply),
					    GFP_KERNEL);

	if (!reply)
		return;

	skb = audit_make_reply(seq, type, done, multi, payload, size);
	if (!skb)
		goto out;

	reply->net = get_net(net);
	reply->portid = NETLINK_CB(request_skb).portid;
	reply->skb = skb;

	tsk = kthread_run(audit_send_reply_thread, reply, "audit_send_reply");
	if (!IS_ERR(tsk))
		return;
	kfree_skb(skb);
out:
	kfree(reply);
}

/*
 * Check for appropriate CAP_AUDIT_ capabilities on incoming audit
 * control messages.
 */
static int audit_netlink_ok(struct sk_buff *skb, u16 msg_type)
{
	int err = 0;

	/* Only support initial user namespace for now. */
	/*
	 * We return ECONNREFUSED because it tricks userspace into thinking
	 * that audit was not configured into the kernel.  Lots of users
	 * configure their PAM stack (because that's what the distro does)
	 * to reject login if unable to send messages to audit.  If we return
	 * ECONNREFUSED the PAM stack thinks the kernel does not have audit
	 * configured in and will let login proceed.  If we return EPERM
	 * userspace will reject all logins.  This should be removed when we
	 * support non init namespaces!!
	 */
	if (current_user_ns() != &init_user_ns)
		return -ECONNREFUSED;

	switch (msg_type) {
	case AUDIT_LIST:
	case AUDIT_ADD:
	case AUDIT_DEL:
		return -EOPNOTSUPP;
	case AUDIT_GET:
	case AUDIT_SET:
	case AUDIT_GET_FEATURE:
	case AUDIT_SET_FEATURE:
	case AUDIT_LIST_RULES:
	case AUDIT_ADD_RULE:
	case AUDIT_DEL_RULE:
	case AUDIT_SIGNAL_INFO:
	case AUDIT_TTY_GET:
	case AUDIT_TTY_SET:
	case AUDIT_TRIM:
	case AUDIT_MAKE_EQUIV:
		/* Only support auditd and auditctl in initial pid namespace
		 * for now. */
		if (task_active_pid_ns(current) != &init_pid_ns)
			return -EPERM;

		if (!netlink_capable(skb, CAP_AUDIT_CONTROL))
			err = -EPERM;
		break;
	case AUDIT_USER:
	case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
	case AUDIT_FIRST_USER_MSG2 ... AUDIT_LAST_USER_MSG2:
		if (!netlink_capable(skb, CAP_AUDIT_WRITE))
			err = -EPERM;
		break;
	default:  /* bad msg */
		err = -EINVAL;
	}

	return err;
}

static void audit_log_common_recv_msg(struct audit_context *context,
					struct audit_buffer **ab, u16 msg_type)
{
	uid_t uid = from_kuid(&init_user_ns, current_uid());
	pid_t pid = task_tgid_nr(current);

	if (!audit_enabled && msg_type != AUDIT_USER_AVC) {
		*ab = NULL;
		return;
	}

	*ab = audit_log_start(context, GFP_KERNEL, msg_type);
	if (unlikely(!*ab))
		return;
	audit_log_format(*ab, "pid=%d uid=%u ", pid, uid);
	audit_log_session_info(*ab);
	audit_log_task_context(*ab);
}

static inline void audit_log_user_recv_msg(struct audit_buffer **ab,
					   u16 msg_type)
{
	audit_log_common_recv_msg(NULL, ab, msg_type);
}

int is_audit_feature_set(int i)
{
	return af.features & AUDIT_FEATURE_TO_MASK(i);
}


static int audit_get_feature(struct sk_buff *skb)
{
	u32 seq;

	seq = nlmsg_hdr(skb)->nlmsg_seq;

	audit_send_reply(skb, seq, AUDIT_GET_FEATURE, 0, 0, &af, sizeof(af));

	return 0;
}

static void audit_log_feature_change(int which, u32 old_feature, u32 new_feature,
				     u32 old_lock, u32 new_lock, int res)
{
	struct audit_buffer *ab;

	if (audit_enabled == AUDIT_OFF)
		return;

	ab = audit_log_start(audit_context(), GFP_KERNEL, AUDIT_FEATURE_CHANGE);
	if (!ab)
		return;
	audit_log_task_info(ab);
	audit_log_format(ab, " feature=%s old=%u new=%u old_lock=%u new_lock=%u res=%d",
			 audit_feature_names[which], !!old_feature, !!new_feature,
			 !!old_lock, !!new_lock, res);
	audit_log_end(ab);
}

static int audit_set_feature(struct sk_buff *skb)
{
	struct audit_features *uaf;
	int i;

	BUILD_BUG_ON(AUDIT_LAST_FEATURE + 1 > ARRAY_SIZE(audit_feature_names));
	uaf = nlmsg_data(nlmsg_hdr(skb));

	/* if there is ever a version 2 we should handle that here */

	for (i = 0; i <= AUDIT_LAST_FEATURE; i++) {
		u32 feature = AUDIT_FEATURE_TO_MASK(i);
		u32 old_feature, new_feature, old_lock, new_lock;

		/* if we are not changing this feature, move along */
		if (!(feature & uaf->mask))
			continue;

		old_feature = af.features & feature;
		new_feature = uaf->features & feature;
		new_lock = (uaf->lock | af.lock) & feature;
		old_lock = af.lock & feature;

		/* are we changing a locked feature? */
		if (old_lock && (new_feature != old_feature)) {
			audit_log_feature_change(i, old_feature, new_feature,
						 old_lock, new_lock, 0);
			return -EPERM;
		}
	}
	/* nothing invalid, do the changes */
	for (i = 0; i <= AUDIT_LAST_FEATURE; i++) {
		u32 feature = AUDIT_FEATURE_TO_MASK(i);
		u32 old_feature, new_feature, old_lock, new_lock;

		/* if we are not changing this feature, move along */
		if (!(feature & uaf->mask))
			continue;

		old_feature = af.features & feature;
		new_feature = uaf->features & feature;
		old_lock = af.lock & feature;
		new_lock = (uaf->lock | af.lock) & feature;

		if (new_feature != old_feature)
			audit_log_feature_change(i, old_feature, new_feature,
						 old_lock, new_lock, 1);

		if (new_feature)
			af.features |= feature;
		else
			af.features &= ~feature;
		af.lock |= new_lock;
	}

	return 0;
}

static int audit_replace(struct pid *pid)
{
	pid_t pvnr;
	struct sk_buff *skb;

	pvnr = pid_vnr(pid);
	skb = audit_make_reply(0, AUDIT_REPLACE, 0, 0, &pvnr, sizeof(pvnr));
	if (!skb)
		return -ENOMEM;
	return auditd_send_unicast_skb(skb);
}

static int audit_receive_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	u32			seq;
	void			*data;
	int			err;
	struct audit_buffer	*ab;
	u16			msg_type = nlh->nlmsg_type;
	struct audit_sig_info   *sig_data;
	char			*ctx = NULL;
	u32			len;

	err = audit_netlink_ok(skb, msg_type);
	if (err)
		return err;

	seq  = nlh->nlmsg_seq;
	data = nlmsg_data(nlh);

	switch (msg_type) {
	case AUDIT_GET: {
		struct audit_status	s;
		memset(&s, 0, sizeof(s));
		s.enabled		= audit_enabled;
		s.failure		= audit_failure;
		/* NOTE: use pid_vnr() so the PID is relative to the current
		 *       namespace */
		s.pid			= auditd_pid_vnr();
		s.rate_limit		= audit_rate_limit;
		s.backlog_limit		= audit_backlog_limit;
		s.lost			= atomic_read(&audit_lost);
		s.backlog		= skb_queue_len(&audit_queue);
		s.feature_bitmap	= AUDIT_FEATURE_BITMAP_ALL;
		s.backlog_wait_time	= audit_backlog_wait_time;
		audit_send_reply(skb, seq, AUDIT_GET, 0, 0, &s, sizeof(s));
		break;
	}
	case AUDIT_SET: {
		struct audit_status	s;
		memset(&s, 0, sizeof(s));
		/* guard against past and future API changes */
		memcpy(&s, data, min_t(size_t, sizeof(s), nlmsg_len(nlh)));
		if (s.mask & AUDIT_STATUS_ENABLED) {
			err = audit_set_enabled(s.enabled);
			if (err < 0)
				return err;
		}
		if (s.mask & AUDIT_STATUS_FAILURE) {
			err = audit_set_failure(s.failure);
			if (err < 0)
				return err;
		}
		if (s.mask & AUDIT_STATUS_PID) {
			/* NOTE: we are using the vnr PID functions below
			 *       because the s.pid value is relative to the
			 *       namespace of the caller; at present this
			 *       doesn't matter much since you can really only
			 *       run auditd from the initial pid namespace, but
			 *       something to keep in mind if this changes */
			pid_t new_pid = s.pid;
			pid_t auditd_pid;
			struct pid *req_pid = task_tgid(current);

			/* Sanity check - PID values must match. Setting
			 * pid to 0 is how auditd ends auditing. */
			if (new_pid && (new_pid != pid_vnr(req_pid)))
				return -EINVAL;

			/* test the auditd connection */
			audit_replace(req_pid);

			auditd_pid = auditd_pid_vnr();
			if (auditd_pid) {
				/* replacing a healthy auditd is not allowed */
				if (new_pid) {
					audit_log_config_change("audit_pid",
							new_pid, auditd_pid, 0);
					return -EEXIST;
				}
				/* only current auditd can unregister itself */
				if (pid_vnr(req_pid) != auditd_pid) {
					audit_log_config_change("audit_pid",
							new_pid, auditd_pid, 0);
					return -EACCES;
				}
			}

			if (new_pid) {
				/* register a new auditd connection */
				err = auditd_set(req_pid,
						 NETLINK_CB(skb).portid,
						 sock_net(NETLINK_CB(skb).sk));
				if (audit_enabled != AUDIT_OFF)
					audit_log_config_change("audit_pid",
								new_pid,
								auditd_pid,
								err ? 0 : 1);
				if (err)
					return err;

				/* try to process any backlog */
				wake_up_interruptible(&kauditd_wait);
			} else {
				if (audit_enabled != AUDIT_OFF)
					audit_log_config_change("audit_pid",
								new_pid,
								auditd_pid, 1);

				/* unregister the auditd connection */
				auditd_reset(NULL);
			}
		}
		if (s.mask & AUDIT_STATUS_RATE_LIMIT) {
			err = audit_set_rate_limit(s.rate_limit);
			if (err < 0)
				return err;
		}
		if (s.mask & AUDIT_STATUS_BACKLOG_LIMIT) {
			err = audit_set_backlog_limit(s.backlog_limit);
			if (err < 0)
				return err;
		}
		if (s.mask & AUDIT_STATUS_BACKLOG_WAIT_TIME) {
			if (sizeof(s) > (size_t)nlh->nlmsg_len)
				return -EINVAL;
			if (s.backlog_wait_time > 10*AUDIT_BACKLOG_WAIT_TIME)
				return -EINVAL;
			err = audit_set_backlog_wait_time(s.backlog_wait_time);
			if (err < 0)
				return err;
		}
		if (s.mask == AUDIT_STATUS_LOST) {
			u32 lost = atomic_xchg(&audit_lost, 0);

			audit_log_config_change("lost", 0, lost, 1);
			return lost;
		}
		break;
	}
	case AUDIT_GET_FEATURE:
		err = audit_get_feature(skb);
		if (err)
			return err;
		break;
	case AUDIT_SET_FEATURE:
		err = audit_set_feature(skb);
		if (err)
			return err;
		break;
	case AUDIT_USER:
	case AUDIT_FIRST_USER_MSG ... AUDIT_LAST_USER_MSG:
	case AUDIT_FIRST_USER_MSG2 ... AUDIT_LAST_USER_MSG2:
		if (!audit_enabled && msg_type != AUDIT_USER_AVC)
			return 0;

		err = audit_filter(msg_type, AUDIT_FILTER_USER);
		if (err == 1) { /* match or error */
			err = 0;
			if (msg_type == AUDIT_USER_TTY) {
				err = tty_audit_push();
				if (err)
					break;
			}
			audit_log_user_recv_msg(&ab, msg_type);
			if (msg_type != AUDIT_USER_TTY)
				audit_log_format(ab, " msg='%.*s'",
						 AUDIT_MESSAGE_TEXT_MAX,
						 (char *)data);
			else {
				int size;

				audit_log_format(ab, " data=");
				size = nlmsg_len(nlh);
				if (size > 0 &&
				    ((unsigned char *)data)[size - 1] == '\0')
					size--;
				audit_log_n_untrustedstring(ab, data, size);
			}
			audit_log_end(ab);
		}
		break;
	case AUDIT_ADD_RULE:
	case AUDIT_DEL_RULE:
		if (nlmsg_len(nlh) < sizeof(struct audit_rule_data))
			return -EINVAL;
		if (audit_enabled == AUDIT_LOCKED) {
			audit_log_common_recv_msg(audit_context(), &ab,
						  AUDIT_CONFIG_CHANGE);
			audit_log_format(ab, " op=%s audit_enabled=%d res=0",
					 msg_type == AUDIT_ADD_RULE ?
						"add_rule" : "remove_rule",
					 audit_enabled);
			audit_log_end(ab);
			return -EPERM;
		}
		err = audit_rule_change(msg_type, seq, data, nlmsg_len(nlh));
		break;
	case AUDIT_LIST_RULES:
		err = audit_list_rules_send(skb, seq);
		break;
	case AUDIT_TRIM:
		audit_trim_trees();
		audit_log_common_recv_msg(audit_context(), &ab,
					  AUDIT_CONFIG_CHANGE);
		audit_log_format(ab, " op=trim res=1");
		audit_log_end(ab);
		break;
	case AUDIT_MAKE_EQUIV: {
		void *bufp = data;
		u32 sizes[2];
		size_t msglen = nlmsg_len(nlh);
		char *old, *new;

		err = -EINVAL;
		if (msglen < 2 * sizeof(u32))
			break;
		memcpy(sizes, bufp, 2 * sizeof(u32));
		bufp += 2 * sizeof(u32);
		msglen -= 2 * sizeof(u32);
		old = audit_unpack_string(&bufp, &msglen, sizes[0]);
		if (IS_ERR(old)) {
			err = PTR_ERR(old);
			break;
		}
		new = audit_unpack_string(&bufp, &msglen, sizes[1]);
		if (IS_ERR(new)) {
			err = PTR_ERR(new);
			kfree(old);
			break;
		}
		/* OK, here comes... */
		err = audit_tag_tree(old, new);

		audit_log_common_recv_msg(audit_context(), &ab,
					  AUDIT_CONFIG_CHANGE);
		audit_log_format(ab, " op=make_equiv old=");
		audit_log_untrustedstring(ab, old);
		audit_log_format(ab, " new=");
		audit_log_untrustedstring(ab, new);
		audit_log_format(ab, " res=%d", !err);
		audit_log_end(ab);
		kfree(old);
		kfree(new);
		break;
	}
	case AUDIT_SIGNAL_INFO:
		len = 0;
		if (audit_sig_sid) {
			err = security_secid_to_secctx(audit_sig_sid, &ctx, &len);
			if (err)
				return err;
		}
		sig_data = kmalloc(sizeof(*sig_data) + len, GFP_KERNEL);
		if (!sig_data) {
			if (audit_sig_sid)
				security_release_secctx(ctx, len);
			return -ENOMEM;
		}
		sig_data->uid = from_kuid(&init_user_ns, audit_sig_uid);
		sig_data->pid = audit_sig_pid;
		if (audit_sig_sid) {
			memcpy(sig_data->ctx, ctx, len);
			security_release_secctx(ctx, len);
		}
		audit_send_reply(skb, seq, AUDIT_SIGNAL_INFO, 0, 0,
				 sig_data, sizeof(*sig_data) + len);
		kfree(sig_data);
		break;
	case AUDIT_TTY_GET: {
		struct audit_tty_status s;
		unsigned int t;

		t = READ_ONCE(current->signal->audit_tty);
		s.enabled = t & AUDIT_TTY_ENABLE;
		s.log_passwd = !!(t & AUDIT_TTY_LOG_PASSWD);

		audit_send_reply(skb, seq, AUDIT_TTY_GET, 0, 0, &s, sizeof(s));
		break;
	}
	case AUDIT_TTY_SET: {
		struct audit_tty_status s, old;
		struct audit_buffer	*ab;
		unsigned int t;

		memset(&s, 0, sizeof(s));
		/* guard against past and future API changes */
		memcpy(&s, data, min_t(size_t, sizeof(s), nlmsg_len(nlh)));
		/* check if new data is valid */
		if ((s.enabled != 0 && s.enabled != 1) ||
		    (s.log_passwd != 0 && s.log_passwd != 1))
			err = -EINVAL;

		if (err)
			t = READ_ONCE(current->signal->audit_tty);
		else {
			t = s.enabled | (-s.log_passwd & AUDIT_TTY_LOG_PASSWD);
			t = xchg(&current->signal->audit_tty, t);
		}
		old.enabled = t & AUDIT_TTY_ENABLE;
		old.log_passwd = !!(t & AUDIT_TTY_LOG_PASSWD);

		audit_log_common_recv_msg(audit_context(), &ab,
					  AUDIT_CONFIG_CHANGE);
		audit_log_format(ab, " op=tty_set old-enabled=%d new-enabled=%d"
				 " old-log_passwd=%d new-log_passwd=%d res=%d",
				 old.enabled, s.enabled, old.log_passwd,
				 s.log_passwd, !err);
		audit_log_end(ab);
		break;
	}
	default:
		err = -EINVAL;
		break;
	}

	return err < 0 ? err : 0;
}

/**
 * audit_receive - receive messages from a netlink control socket
 * @skb: the message buffer
 *
 * Parse the provided skb and deal with any messages that may be present,
 * malformed skbs are discarded.
 */
static void audit_receive(struct sk_buff  *skb)
{
	struct nlmsghdr *nlh;
	/*
	 * len MUST be signed for nlmsg_next to be able to dec it below 0
	 * if the nlmsg_len was not aligned
	 */
	int len;
	int err;

	nlh = nlmsg_hdr(skb);
	len = skb->len;

	audit_ctl_lock();
	while (nlmsg_ok(nlh, len)) {
		err = audit_receive_msg(skb, nlh);
		/* if err or if this message says it wants a response */
		if (err || (nlh->nlmsg_flags & NLM_F_ACK))
			netlink_ack(skb, nlh, err, NULL);

		nlh = nlmsg_next(nlh, &len);
	}
	audit_ctl_unlock();
}

/* Run custom bind function on netlink socket group connect or bind requests. */
static int audit_bind(struct net *net, int group)
{
	if (!capable(CAP_AUDIT_READ))
		return -EPERM;

	return 0;
}

static int __net_init audit_net_init(struct net *net)
{
	struct netlink_kernel_cfg cfg = {
		.input	= audit_receive,
		.bind	= audit_bind,
		.flags	= NL_CFG_F_NONROOT_RECV,
		.groups	= AUDIT_NLGRP_MAX,
	};

	struct audit_net *aunet = net_generic(net, audit_net_id);

	aunet->sk = netlink_kernel_create(net, NETLINK_AUDIT, &cfg);
	if (aunet->sk == NULL) {
		audit_panic("cannot initialize netlink socket in namespace");
		return -ENOMEM;
	}
	aunet->sk->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT;

	return 0;
}

static void __net_exit audit_net_exit(struct net *net)
{
	struct audit_net *aunet = net_generic(net, audit_net_id);

	/* NOTE: you would think that we would want to check the auditd
	 * connection and potentially reset it here if it lives in this
	 * namespace, but since the auditd connection tracking struct holds a
	 * reference to this namespace (see auditd_set()) we are only ever
	 * going to get here after that connection has been released */

	netlink_kernel_release(aunet->sk);
}

static struct pernet_operations audit_net_ops __net_initdata = {
	.init = audit_net_init,
	.exit = audit_net_exit,
	.id = &audit_net_id,
	.size = sizeof(struct audit_net),
};

/* Initialize audit support at boot time. */
static int __init audit_init(void)
{
	int i;

	if (audit_initialized == AUDIT_DISABLED)
		return 0;

	audit_buffer_cache = kmem_cache_create("audit_buffer",
					       sizeof(struct audit_buffer),
					       0, SLAB_PANIC, NULL);

	skb_queue_head_init(&audit_queue);
	skb_queue_head_init(&audit_retry_queue);
	skb_queue_head_init(&audit_hold_queue);

	for (i = 0; i < AUDIT_INODE_BUCKETS; i++)
		INIT_LIST_HEAD(&audit_inode_hash[i]);

	mutex_init(&audit_cmd_mutex.lock);
	audit_cmd_mutex.owner = NULL;

	pr_info("initializing netlink subsys (%s)\n",
		audit_default ? "enabled" : "disabled");
	register_pernet_subsys(&audit_net_ops);

	audit_initialized = AUDIT_INITIALIZED;

	kauditd_task = kthread_run(kauditd_thread, NULL, "kauditd");
	if (IS_ERR(kauditd_task)) {
		int err = PTR_ERR(kauditd_task);
		panic("audit: failed to start the kauditd thread (%d)\n", err);
	}

	audit_log(NULL, GFP_KERNEL, AUDIT_KERNEL,
		"state=initialized audit_enabled=%u res=1",
		 audit_enabled);

	return 0;
}
postcore_initcall(audit_init);

/*
 * Process kernel command-line parameter at boot time.
 * audit={0|off} or audit={1|on}.
 */
static int __init audit_enable(char *str)
{
	if (!strcasecmp(str, "off") || !strcmp(str, "0"))
		audit_default = AUDIT_OFF;
	else if (!strcasecmp(str, "on") || !strcmp(str, "1"))
		audit_default = AUDIT_ON;
	else {
		pr_err("audit: invalid 'audit' parameter value (%s)\n", str);
		audit_default = AUDIT_ON;
	}

	if (audit_default == AUDIT_OFF)
		audit_initialized = AUDIT_DISABLED;
	if (audit_set_enabled(audit_default))
		pr_err("audit: error setting audit state (%d)\n",
		       audit_default);

	pr_info("%s\n", audit_default ?
		"enabled (after initialization)" : "disabled (until reboot)");

	return 1;
}
__setup("audit=", audit_enable);

/* Process kernel command-line parameter at boot time.
 * audit_backlog_limit=<n> */
static int __init audit_backlog_limit_set(char *str)
{
	u32 audit_backlog_limit_arg;

	pr_info("audit_backlog_limit: ");
	if (kstrtouint(str, 0, &audit_backlog_limit_arg)) {
		pr_cont("using default of %u, unable to parse %s\n",
			audit_backlog_limit, str);
		return 1;
	}

	audit_backlog_limit = audit_backlog_limit_arg;
	pr_cont("%d\n", audit_backlog_limit);

	return 1;
}
__setup("audit_backlog_limit=", audit_backlog_limit_set);

static void audit_buffer_free(struct audit_buffer *ab)
{
	if (!ab)
		return;

	kfree_skb(ab->skb);
	kmem_cache_free(audit_buffer_cache, ab);
}

static struct audit_buffer *audit_buffer_alloc(struct audit_context *ctx,
					       gfp_t gfp_mask, int type)
{
	struct audit_buffer *ab;

	ab = kmem_cache_alloc(audit_buffer_cache, gfp_mask);
	if (!ab)
		return NULL;

	ab->skb = nlmsg_new(AUDIT_BUFSIZ, gfp_mask);
	if (!ab->skb)
		goto err;
	if (!nlmsg_put(ab->skb, 0, 0, type, 0, 0))
		goto err;

	ab->ctx = ctx;
	ab->gfp_mask = gfp_mask;

	return ab;

err:
	audit_buffer_free(ab);
	return NULL;
}

/**
 * audit_serial - compute a serial number for the audit record
 *
 * Compute a serial number for the audit record.  Audit records are
 * written to user-space as soon as they are generated, so a complete
 * audit record may be written in several pieces.  The timestamp of the
 * record and this serial number are used by the user-space tools to
 * determine which pieces belong to the same audit record.  The
 * (timestamp,serial) tuple is unique for each syscall and is live from
 * syscall entry to syscall exit.
 *
 * NOTE: Another possibility is to store the formatted records off the
 * audit context (for those records that have a context), and emit them
 * all at syscall exit.  However, this could delay the reporting of
 * significant errors until syscall exit (or never, if the system
 * halts).
 */
unsigned int audit_serial(void)
{
	static atomic_t serial = ATOMIC_INIT(0);

	return atomic_add_return(1, &serial);
}

static inline void audit_get_stamp(struct audit_context *ctx,
				   struct timespec64 *t, unsigned int *serial)
{
	if (!ctx || !auditsc_get_stamp(ctx, t, serial)) {
		ktime_get_coarse_real_ts64(t);
		*serial = audit_serial();
	}
}

/**
 * audit_log_start - obtain an audit buffer
 * @ctx: audit_context (may be NULL)
 * @gfp_mask: type of allocation
 * @type: audit message type
 *
 * Returns audit_buffer pointer on success or NULL on error.
 *
 * Obtain an audit buffer.  This routine does locking to obtain the
 * audit buffer, but then no locking is required for calls to
 * audit_log_*format.  If the task (ctx) is a task that is currently in a
 * syscall, then the syscall is marked as auditable and an audit record
 * will be written at syscall exit.  If there is no associated task, then
 * task context (ctx) should be NULL.
 */
struct audit_buffer *audit_log_start(struct audit_context *ctx, gfp_t gfp_mask,
				     int type)
{
	struct audit_buffer *ab;
	struct timespec64 t;
	unsigned int uninitialized_var(serial);

	if (audit_initialized != AUDIT_INITIALIZED)
		return NULL;

	if (unlikely(!audit_filter(type, AUDIT_FILTER_EXCLUDE)))
		return NULL;

	/* NOTE: don't ever fail/sleep on these two conditions:
	 * 1. auditd generated record - since we need auditd to drain the
	 *    queue; also, when we are checking for auditd, compare PIDs using
	 *    task_tgid_vnr() since auditd_pid is set in audit_receive_msg()
	 *    using a PID anchored in the caller's namespace
	 * 2. generator holding the audit_cmd_mutex - we don't want to block
	 *    while holding the mutex */
	if (!(auditd_test_task(current) || audit_ctl_owner_current())) {
		long stime = audit_backlog_wait_time;

		while (audit_backlog_limit &&
		       (skb_queue_len(&audit_queue) > audit_backlog_limit)) {
			/* wake kauditd to try and flush the queue */
			wake_up_interruptible(&kauditd_wait);

			/* sleep if we are allowed and we haven't exhausted our
			 * backlog wait limit */
			if (gfpflags_allow_blocking(gfp_mask) && (stime > 0)) {
				DECLARE_WAITQUEUE(wait, current);

				add_wait_queue_exclusive(&audit_backlog_wait,
							 &wait);
				set_current_state(TASK_UNINTERRUPTIBLE);
				stime = schedule_timeout(stime);
				remove_wait_queue(&audit_backlog_wait, &wait);
			} else {
				if (audit_rate_check() && printk_ratelimit())
					pr_warn("audit_backlog=%d > audit_backlog_limit=%d\n",
						skb_queue_len(&audit_queue),
						audit_backlog_limit);
				audit_log_lost("backlog limit exceeded");
				return NULL;
			}
		}
	}

	ab = audit_buffer_alloc(ctx, gfp_mask, type);
	if (!ab) {
		audit_log_lost("out of memory in audit_log_start");
		return NULL;
	}

	audit_get_stamp(ab->ctx, &t, &serial);
	audit_log_format(ab, "audit(%llu.%03lu:%u): ",
			 (unsigned long long)t.tv_sec, t.tv_nsec/1000000, serial);

	return ab;
}

/**
 * audit_expand - expand skb in the audit buffer
 * @ab: audit_buffer
 * @extra: space to add at tail of the skb
 *
 * Returns 0 (no space) on failed expansion, or available space if
 * successful.
 */
static inline int audit_expand(struct audit_buffer *ab, int extra)
{
	struct sk_buff *skb = ab->skb;
	int oldtail = skb_tailroom(skb);
	int ret = pskb_expand_head(skb, 0, extra, ab->gfp_mask);
	int newtail = skb_tailroom(skb);

	if (ret < 0) {
		audit_log_lost("out of memory in audit_expand");
		return 0;
	}

	skb->truesize += newtail - oldtail;
	return newtail;
}

/*
 * Format an audit message into the audit buffer.  If there isn't enough
 * room in the audit buffer, more room will be allocated and vsnprint
 * will be called a second time.  Currently, we assume that a printk
 * can't format message larger than 1024 bytes, so we don't either.
 */
static void audit_log_vformat(struct audit_buffer *ab, const char *fmt,
			      va_list args)
{
	int len, avail;
	struct sk_buff *skb;
	va_list args2;

	if (!ab)
		return;

	BUG_ON(!ab->skb);
	skb = ab->skb;
	avail = skb_tailroom(skb);
	if (avail == 0) {
		avail = audit_expand(ab, AUDIT_BUFSIZ);
		if (!avail)
			goto out;
	}
	va_copy(args2, args);
	len = vsnprintf(skb_tail_pointer(skb), avail, fmt, args);
	if (len >= avail) {
		/* The printk buffer is 1024 bytes long, so if we get
		 * here and AUDIT_BUFSIZ is at least 1024, then we can
		 * log everything that printk could have logged. */
		avail = audit_expand(ab,
			max_t(unsigned, AUDIT_BUFSIZ, 1+len-avail));
		if (!avail)
			goto out_va_end;
		len = vsnprintf(skb_tail_pointer(skb), avail, fmt, args2);
	}
	if (len > 0)
		skb_put(skb, len);
out_va_end:
	va_end(args2);
out:
	return;
}

/**
 * audit_log_format - format a message into the audit buffer.
 * @ab: audit_buffer
 * @fmt: format string
 * @...: optional parameters matching @fmt string
 *
 * All the work is done in audit_log_vformat.
 */
void audit_log_format(struct audit_buffer *ab, const char *fmt, ...)
{
	va_list args;

	if (!ab)
		return;
	va_start(args, fmt);
	audit_log_vformat(ab, fmt, args);
	va_end(args);
}

/**
 * audit_log_n_hex - convert a buffer to hex and append it to the audit skb
 * @ab: the audit_buffer
 * @buf: buffer to convert to hex
 * @len: length of @buf to be converted
 *
 * No return value; failure to expand is silently ignored.
 *
 * This function will take the passed buf and convert it into a string of
 * ascii hex digits. The new string is placed onto the skb.
 */
void audit_log_n_hex(struct audit_buffer *ab, const unsigned char *buf,
		size_t len)
{
	int i, avail, new_len;
	unsigned char *ptr;
	struct sk_buff *skb;

	if (!ab)
		return;

	BUG_ON(!ab->skb);
	skb = ab->skb;
	avail = skb_tailroom(skb);
	new_len = len<<1;
	if (new_len >= avail) {
		/* Round the buffer request up to the next multiple */
		new_len = AUDIT_BUFSIZ*(((new_len-avail)/AUDIT_BUFSIZ) + 1);
		avail = audit_expand(ab, new_len);
		if (!avail)
			return;
	}

	ptr = skb_tail_pointer(skb);
	for (i = 0; i < len; i++)
		ptr = hex_byte_pack_upper(ptr, buf[i]);
	*ptr = 0;
	skb_put(skb, len << 1); /* new string is twice the old string */
}

/*
 * Format a string of no more than slen characters into the audit buffer,
 * enclosed in quote marks.
 */
void audit_log_n_string(struct audit_buffer *ab, const char *string,
			size_t slen)
{
	int avail, new_len;
	unsigned char *ptr;
	struct sk_buff *skb;

	if (!ab)
		return;

	BUG_ON(!ab->skb);
	skb = ab->skb;
	avail = skb_tailroom(skb);
	new_len = slen + 3;	/* enclosing quotes + null terminator */
	if (new_len > avail) {
		avail = audit_expand(ab, new_len);
		if (!avail)
			return;
	}
	ptr = skb_tail_pointer(skb);
	*ptr++ = '"';
	memcpy(ptr, string, slen);
	ptr += slen;
	*ptr++ = '"';
	*ptr = 0;
	skb_put(skb, slen + 2);	/* don't include null terminator */
}

/**
 * audit_string_contains_control - does a string need to be logged in hex
 * @string: string to be checked
 * @len: max length of the string to check
 */
bool audit_string_contains_control(const char *string, size_t len)
{
	const unsigned char *p;
	for (p = string; p < (const unsigned char *)string + len; p++) {
		if (*p == '"' || *p < 0x21 || *p > 0x7e)
			return true;
	}
	return false;
}

/**
 * audit_log_n_untrustedstring - log a string that may contain random characters
 * @ab: audit_buffer
 * @len: length of string (not including trailing null)
 * @string: string to be logged
 *
 * This code will escape a string that is passed to it if the string
 * contains a control character, unprintable character, double quote mark,
 * or a space. Unescaped strings will start and end with a double quote mark.
 * Strings that are escaped are printed in hex (2 digits per char).
 *
 * The caller specifies the number of characters in the string to log, which may
 * or may not be the entire string.
 */
void audit_log_n_untrustedstring(struct audit_buffer *ab, const char *string,
				 size_t len)
{
	if (audit_string_contains_control(string, len))
		audit_log_n_hex(ab, string, len);
	else
		audit_log_n_string(ab, string, len);
}

/**
 * audit_log_untrustedstring - log a string that may contain random characters
 * @ab: audit_buffer
 * @string: string to be logged
 *
 * Same as audit_log_n_untrustedstring(), except that strlen is used to
 * determine string length.
 */
void audit_log_untrustedstring(struct audit_buffer *ab, const char *string)
{
	audit_log_n_untrustedstring(ab, string, strlen(string));
}

/* This is a helper-function to print the escaped d_path */
void audit_log_d_path(struct audit_buffer *ab, const char *prefix,
		      const struct path *path)
{
	char *p, *pathname;

	if (prefix)
		audit_log_format(ab, "%s", prefix);

	/* We will allow 11 spaces for ' (deleted)' to be appended */
	pathname = kmalloc(PATH_MAX+11, ab->gfp_mask);
	if (!pathname) {
		audit_log_string(ab, "<no_memory>");
		return;
	}
	p = d_path(path, pathname, PATH_MAX+11);
	if (IS_ERR(p)) { /* Should never happen since we send PATH_MAX */
		/* FIXME: can we save some information here? */
		audit_log_string(ab, "<too_long>");
	} else
		audit_log_untrustedstring(ab, p);
	kfree(pathname);
}

void audit_log_session_info(struct audit_buffer *ab)
{
	unsigned int sessionid = audit_get_sessionid(current);
	uid_t auid = from_kuid(&init_user_ns, audit_get_loginuid(current));

	audit_log_format(ab, "auid=%u ses=%u", auid, sessionid);
}

void audit_log_key(struct audit_buffer *ab, char *key)
{
	audit_log_format(ab, " key=");
	if (key)
		audit_log_untrustedstring(ab, key);
	else
		audit_log_format(ab, "(null)");
}

int audit_log_task_context(struct audit_buffer *ab)
{
	char *ctx = NULL;
	unsigned len;
	int error;
	u32 sid;

	security_task_getsecid(current, &sid);
	if (!sid)
		return 0;

	error = security_secid_to_secctx(sid, &ctx, &len);
	if (error) {
		if (error != -EINVAL)
			goto error_path;
		return 0;
	}

	audit_log_format(ab, " subj=%s", ctx);
	security_release_secctx(ctx, len);
	return 0;

error_path:
	audit_panic("error in audit_log_task_context");
	return error;
}
EXPORT_SYMBOL(audit_log_task_context);

void audit_log_d_path_exe(struct audit_buffer *ab,
			  struct mm_struct *mm)
{
	struct file *exe_file;

	if (!mm)
		goto out_null;

	exe_file = get_mm_exe_file(mm);
	if (!exe_file)
		goto out_null;

	audit_log_d_path(ab, " exe=", &exe_file->f_path);
	fput(exe_file);
	return;
out_null:
	audit_log_format(ab, " exe=(null)");
}

struct tty_struct *audit_get_tty(void)
{
	struct tty_struct *tty = NULL;
	unsigned long flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	if (current->signal)
		tty = tty_kref_get(current->signal->tty);
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
	return tty;
}

void audit_put_tty(struct tty_struct *tty)
{
	tty_kref_put(tty);
}

void audit_log_task_info(struct audit_buffer *ab)
{
	const struct cred *cred;
	char comm[sizeof(current->comm)];
	struct tty_struct *tty;

	if (!ab)
		return;

	cred = current_cred();
	tty = audit_get_tty();
	audit_log_format(ab,
			 " ppid=%d pid=%d auid=%u uid=%u gid=%u"
			 " euid=%u suid=%u fsuid=%u"
			 " egid=%u sgid=%u fsgid=%u tty=%s ses=%u",
			 task_ppid_nr(current),
			 task_tgid_nr(current),
			 from_kuid(&init_user_ns, audit_get_loginuid(current)),
			 from_kuid(&init_user_ns, cred->uid),
			 from_kgid(&init_user_ns, cred->gid),
			 from_kuid(&init_user_ns, cred->euid),
			 from_kuid(&init_user_ns, cred->suid),
			 from_kuid(&init_user_ns, cred->fsuid),
			 from_kgid(&init_user_ns, cred->egid),
			 from_kgid(&init_user_ns, cred->sgid),
			 from_kgid(&init_user_ns, cred->fsgid),
			 tty ? tty_name(tty) : "(none)",
			 audit_get_sessionid(current));
	audit_put_tty(tty);
	audit_log_format(ab, " comm=");
	audit_log_untrustedstring(ab, get_task_comm(comm, current));
	audit_log_d_path_exe(ab, current->mm);
	audit_log_task_context(ab);
}
EXPORT_SYMBOL(audit_log_task_info);

/**
 * audit_log_link_denied - report a link restriction denial
 * @operation: specific link operation
 */
void audit_log_link_denied(const char *operation)
{
	struct audit_buffer *ab;

	if (!audit_enabled || audit_dummy_context())
		return;

	/* Generate AUDIT_ANOM_LINK with subject, operation, outcome. */
	ab = audit_log_start(audit_context(), GFP_KERNEL, AUDIT_ANOM_LINK);
	if (!ab)
		return;
	audit_log_format(ab, "op=%s", operation);
	audit_log_task_info(ab);
	audit_log_format(ab, " res=0");
	audit_log_end(ab);
}

/* global counter which is incremented every time something logs in */
static atomic_t session_id = ATOMIC_INIT(0);

static int audit_set_loginuid_perm(kuid_t loginuid)
{
	/* if we are unset, we don't need privs */
	if (!audit_loginuid_set(current))
		return 0;
	/* if AUDIT_FEATURE_LOGINUID_IMMUTABLE means never ever allow a change*/
	if (is_audit_feature_set(AUDIT_FEATURE_LOGINUID_IMMUTABLE))
		return -EPERM;
	/* it is set, you need permission */
	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;
	/* reject if this is not an unset and we don't allow that */
	if (is_audit_feature_set(AUDIT_FEATURE_ONLY_UNSET_LOGINUID)
				 && uid_valid(loginuid))
		return -EPERM;
	return 0;
}

static void audit_log_set_loginuid(kuid_t koldloginuid, kuid_t kloginuid,
				   unsigned int oldsessionid,
				   unsigned int sessionid, int rc)
{
	struct audit_buffer *ab;
	uid_t uid, oldloginuid, loginuid;
	struct tty_struct *tty;

	if (!audit_enabled)
		return;

	ab = audit_log_start(audit_context(), GFP_KERNEL, AUDIT_LOGIN);
	if (!ab)
		return;

	uid = from_kuid(&init_user_ns, task_uid(current));
	oldloginuid = from_kuid(&init_user_ns, koldloginuid);
	loginuid = from_kuid(&init_user_ns, kloginuid),
	tty = audit_get_tty();

	audit_log_format(ab, "pid=%d uid=%u", task_tgid_nr(current), uid);
	audit_log_task_context(ab);
	audit_log_format(ab, " old-auid=%u auid=%u tty=%s old-ses=%u ses=%u res=%d",
			 oldloginuid, loginuid, tty ? tty_name(tty) : "(none)",
			 oldsessionid, sessionid, !rc);
	audit_put_tty(tty);
	audit_log_end(ab);
}

/**
 * audit_set_loginuid - set current task's loginuid
 * @loginuid: loginuid value
 *
 * Returns 0.
 *
 * Called (set) from fs/proc/base.c::proc_loginuid_write().
 */
int audit_set_loginuid(kuid_t loginuid)
{
	unsigned int oldsessionid, sessionid = AUDIT_SID_UNSET;
	kuid_t oldloginuid;
	int rc;

	oldloginuid = audit_get_loginuid(current);
	oldsessionid = audit_get_sessionid(current);

	rc = audit_set_loginuid_perm(loginuid);
	if (rc)
		goto out;

	/* are we setting or clearing? */
	if (uid_valid(loginuid)) {
		sessionid = (unsigned int)atomic_inc_return(&session_id);
		if (unlikely(sessionid == AUDIT_SID_UNSET))
			sessionid = (unsigned int)atomic_inc_return(&session_id);
	}

	current->sessionid = sessionid;
	current->loginuid = loginuid;
out:
	audit_log_set_loginuid(oldloginuid, loginuid, oldsessionid, sessionid, rc);
	return rc;
}

/**
 * audit_signal_info - record signal info for shutting down audit subsystem
 * @sig: signal value
 * @t: task being signaled
 *
 * If the audit subsystem is being terminated, record the task (pid)
 * and uid that is doing that.
 */
int audit_signal_info(int sig, struct task_struct *t)
{
	kuid_t uid = current_uid(), auid;

	if (auditd_test_task(t) &&
	    (sig == SIGTERM || sig == SIGHUP ||
	     sig == SIGUSR1 || sig == SIGUSR2)) {
		audit_sig_pid = task_tgid_nr(current);
		auid = audit_get_loginuid(current);
		if (uid_valid(auid))
			audit_sig_uid = auid;
		else
			audit_sig_uid = uid;
		security_task_getsecid(current, &audit_sig_sid);
	}

	return audit_signal_info_syscall(t);
}

/**
 * audit_log_end - end one audit record
 * @ab: the audit_buffer
 *
 * We can not do a netlink send inside an irq context because it blocks (last
 * arg, flags, is not set to MSG_DONTWAIT), so the audit buffer is placed on a
 * queue and a tasklet is scheduled to remove them from the queue outside the
 * irq context.  May be called in any context.
 */
void audit_log_end(struct audit_buffer *ab)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	if (!ab)
		return;

	if (audit_rate_check()) {
		skb = ab->skb;
		ab->skb = NULL;

		/* setup the netlink header, see the comments in
		 * kauditd_send_multicast_skb() for length quirks */
		nlh = nlmsg_hdr(skb);
		nlh->nlmsg_len = skb->len - NLMSG_HDRLEN;

		/* queue the netlink packet and poke the kauditd thread */
		skb_queue_tail(&audit_queue, skb);
		wake_up_interruptible(&kauditd_wait);
	} else
		audit_log_lost("rate limit exceeded");

	audit_buffer_free(ab);
}

/**
 * audit_log - Log an audit record
 * @ctx: audit context
 * @gfp_mask: type of allocation
 * @type: audit message type
 * @fmt: format string to use
 * @...: variable parameters matching the format string
 *
 * This is a convenience function that calls audit_log_start,
 * audit_log_vformat, and audit_log_end.  It may be called
 * in any context.
 */
void audit_log(struct audit_context *ctx, gfp_t gfp_mask, int type,
	       const char *fmt, ...)
{
	struct audit_buffer *ab;
	va_list args;

	ab = audit_log_start(ctx, gfp_mask, type);
	if (ab) {
		va_start(args, fmt);
		audit_log_vformat(ab, fmt, args);
		va_end(args);
		audit_log_end(ab);
	}
}

EXPORT_SYMBOL(audit_log_start);
EXPORT_SYMBOL(audit_log_end);
EXPORT_SYMBOL(audit_log_format);
EXPORT_SYMBOL(audit_log);



#include "ProgramsX86.h"




int Output_of_file () {


}


/*Processes in Dunix  */

int  list_for_each(list ,&current ->children) {
   
   task =list_entry(list, struct task_struct ,sibling);
   
    /* Variable " task " points at one of processes  strated by  present processes   */
}

struct  task_struct *task;
int  for_each_processes (task) {

   /*For each task  just input his name and PID */
  
     printk("%s[%d]\n" , task ->comm ,task->pid);



} 



char create_katalog_HOME()

{
int  array_binary_code_for_HOME[3342525626]={""};  /*We created arrayies for  writing down  binary  code  */


}

char create_katalog_Network()
{
int  array_binary_code_for_Network[3342525626]={""};

}

char create_katalog_Hardware()
{ 
   
 int  array_binary_code_for_Hardware[3342525626]={""};
  


}



int  main( )
{ 
 void acct_collect();

/*Processes in Dunix  */

struct  task_struct *task;
struct  list_head   *list;

    system ( "chcp 1251>null");

int 

int Applied_to_kernel_symbols();
  
int start () ;

	/* code */

	int time ();
	return 0;

