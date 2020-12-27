#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

#ifdef _MSC_VER
# define __unused /**/ // TODO - Should just not declare parameters or use (void)param
# define UNUSED_ENUM /**/ // TODO
# define FLAG_ENUM /**/ // TODO
# define __printflike(a, b) /**/
# pragma warning(1:4820)
#else
# define UNUSED_ENUM __attribute__((unused))
# define FLAG_ENUM __attribute__((clang::flag_enum))
#endif // _MSC_VER

#define ASSERT_SIZEOF(t, s) do { \
		_Static_assert(sizeof(t) < s + 1, "sizeof(" #t ") should be " #s " but is >= " #s " + 1"); \
		_Static_assert(sizeof(t) > s - 1, "sizeof(" #t ") should be " #s " but is <= " #s " - 1"); \
	} while (0)

#define BIT(n) (1 << (n))

#ifdef __INTELLISENSE__
	#define INTERFACE 1
#endif // __INTELLISENSE__
