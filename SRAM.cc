#include "Types.hh"
#include "OS.hh"
#include "SRAM.Gen.hh"

bool
sram_init(void)
{
	os_perm_mask dummy_perm;
	(void)dummy_perm;

	// TODO: load save file
	return mem_seg_alloc(MEM_SEG_SRAM, 8 << 10, os_perm_mask::READ | os_perm_mask::WRITE);
}

void
sram_fini(void)
{
	mem_seg_free(MEM_SEG_SRAM);
	// TODO: write save file
}
