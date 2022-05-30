/* This file was automatically generated.  Do not edit! */
typedef u_int8_t *bitset_t;
void bitset_destroy(bitset_t bitset);
void bitset_set(bitset_t bitset,u_int index);
bool bitset_is_set(bitset_t bitset,u_int index);
#include <stdarg.h>
enum os_runerr_type {
		OS_RUNERR_TYPE_OSERR,
		OS_RUNERR_TYPE_WARNING,
		OS_RUNERR_TYPE_EMULATION
	};
enum os_runerr_type;
void main_fatal_error(enum os_runerr_type type,const char *fmt,...);
void main_fatal_error(enum os_runerr_type type,const char *fmt,...);
bitset_t bitset_create(u_int num_bits);
#define INTERFACE 0
