#include "types.h"
#include "bitset.h"

#include <stdlib.h>

#if INTERFACE
	typedef u_int8_t *bitset_t;
#endif // INTERFACE

bitset_t
bitset_create(u_int num_bits)
{
	size_t num_bytes = (num_bits + 7) / 8;

	u_int8_t *bitset = calloc(num_bytes, 1);
	if (!bitset)
		main_fatal_error(OS_RUNERR_TYPE_OSERR, "Allocate bitset (size=%u)", num_bytes);

	return bitset;
}

bool
bitset_is_set(bitset_t bitset, u_int index)
{
	u_int8_t mask = 1u << (index % 8);

	return (bitset[index / 8] & mask);
}

void
bitset_set(bitset_t bitset, u_int index)
{
	u_int8_t mask = 1u << (index % 8);

	bitset[index / 8] |= mask;
}

void
bitset_destroy(bitset_t bitset)
{
	free(bitset);
}
