#include "types.h"
#include "sram.h"

bool
sram_init(void)
{
	enum os_perm dummy_perm;
	(void)dummy_perm;

	// TODO: load save file
	return mem_seg_alloc(MEM_SEG_SRAM, 8 << 10, OS_PERM_READ | OS_PERM_WRITE);
}

void
sram_fini(void)
{
	mem_seg_free(MEM_SEG_SRAM);
	// TODO: write save file
}
