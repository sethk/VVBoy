#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

#define assert_sizeof(t, s) do { \
		static_assert(sizeof(t) < s + 1, "sizeof(" #t ") should be " #s " but is >= " #s " + 1"); \
		static_assert(sizeof(t) > s - 1, "sizeof(" #t ") should be " #s " but is <= " #s " - 1"); \
	} while (0)

#ifdef _MSC_VER
# define __unused /**/ // TODO - Should just not declare parameters or use (void)param
# define __printflike(a, b) /**/
#endif // _MSC_VER

#define BIT(n) (1 << (n))

enum os_perm
{
	OS_PERM_READ = BIT(0),
	OS_PERM_WRITE = BIT(1),
	OS_PERM_EXEC = BIT(2)
};

enum os_seek_anchor
{
	OS_SEEK_SET,
	OS_SEEK_CUR,
	OS_SEEK_END
};

enum os_runerr_type
{
	OS_RUNERR_TYPE_OSERR,
	OS_RUNERR_TYPE_WARNING,
	OS_RUNERR_TYPE_EMULATION
};

enum os_runerr_resp
{
	OS_RUNERR_RESP_OKAY,
	OS_RUNERR_RESP_IGNORE,
	OS_RUNERR_RESP_ALWAYS_IGNORE,
	OS_RUNERR_RESP_DEBUG,
	OS_RUNERR_RESP_ABORT,
	OS_RUNERR_NUM_RESP
};

#ifdef __INTELLISENSE__
	#define INTERFACE 1
#endif // __INTELLISENSE__
