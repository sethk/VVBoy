#include "types.h"
#include "wram.h"

#define WRAM_SIZE 0x1000000

bool
wram_init(void)
{
	enum os_perm dummy_perm;
	(void)dummy_perm;

	return mem_seg_alloc(MEM_SEG_WRAM, WRAM_SIZE, OS_PERM_READ | OS_PERM_WRITE);
}

void
wram_init_debug()
{
	debug_create_symbol("GLOBAL", 0x05000000, true);
	debug_create_symbol("STACK", 0x0500dfff, true);
}

void
wram_fini(void)
{
	mem_seg_free(MEM_SEG_WRAM);
}
