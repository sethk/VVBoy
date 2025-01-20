#include "Memory.hh"
#include "SRAM.Gen.hh"

bool
sram_init(void)
{
	os_perm_mask dummy_perm;
	(void)dummy_perm;

	// TODO: load save file
	return mem.Segments[Memory::SEG_SRAM].Allocate(8 << 10, os_perm_mask::READ | os_perm_mask::WRITE);
}

void
sram_fini(void)
{
	mem.Segments[Memory::SEG_SRAM].Free();
	// TODO: write save file
}
