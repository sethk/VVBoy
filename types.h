#pragma once

#include <stdint.h>
#include <stdbool.h>
#define _SEARCH_PRIVATE
#include <search.h>
#undef _SEARCH_PRIVATE

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
# define ENABLE_PADDING_WARNING __pragma(warning(1:4820))
# define DISABLE_PADDING_WARNING __pragma(warning(disable:4820))
# define STATIC_ASSERT static_assert
#else
# define UNUSED_ENUM __attribute__((unused))
# define FLAG_ENUM __attribute__((clang::flag_enum))
# define DISABLE_PADDING_WARNING
# define ENABLE_PADDING_WARNING
# define STATIC_ASSERT _Static_assert
#endif // _MSC_VER

#define ASSERT_SIZEOF(t, s) do { \
		STATIC_ASSERT(sizeof(t) < s + 1, "sizeof(" #t ") should be " #s " but is >= " #s " + 1"); \
		STATIC_ASSERT(sizeof(t) > s - 1, "sizeof(" #t ") should be " #s " but is <= " #s " - 1"); \
	} while (0)

#define BIT(n) (1 << (n))

#define COUNT_OF(a) (sizeof(a) / sizeof(a[0]))

#ifndef NO_IMGUI_TYPES
# define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
# include <cimgui/cimgui.h>
#endif // !NO_IMGUI_TYPES

inline static int min_int(int a, int b) { return (a < b) ? a : b; }
inline static int max_int(int a, int b) { return (a > b) ? a : b; }
inline static u_int min_uint(u_int a, u_int b) { return (a < b) ? a : b; }
inline static u_int max_uint(u_int a, u_int b) { return (a > b) ? a : b; }
inline static u_int64_t min_uint64(u_int64_t a, u_int64_t b) { return (a < b) ? a : b; }
inline static u_int64_t max_uint64(u_int64_t a, u_int64_t b) { return (a > b) ? a : b; }
inline static u_int64_t clamp_uint64(u_int x, u_int min, u_int max) { return min_uint64(max_uint64(x, min), max); }

#ifdef __INTELLISENSE__
	#define INTERFACE 1
#endif // __INTELLISENSE__
